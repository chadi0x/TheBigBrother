/* ==========================================================================
   THE BIG BROTHER // V7.0 TACTICAL FORENSIC SYSTEM
   FULL-SPECTRUM COMPANION POWER TOOLS RUNTIME ENGINE
   CLASSIFIED // ALL 26 TABS TACTICAL SUBTOOL WORKSPACE
   ========================================================================== */

// Helper to escape HTML
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/* ============================================================
   1. TAB-HUDSONROCK COMPANION: RAW STEALER LOG PARSER
   ============================================================ */
window.runStealerParser = async function() {
    const input = document.getElementById('stealer-raw-input')?.value || '';
    const status = document.getElementById('stealerparser-status');
    const results = document.getElementById('stealerparser-results');
    if (!input.trim()) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Paste raw stealer log buffer first</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> PARSING LOG ARCHIVE...</span>`;
    if (results) results.innerHTML = `<div style="padding:24px; text-align:center;" class="mono cyan"><span class="engine-pulse-dot"></span> Parsing credentials, tokens, and browser cookies...</div>`;

    try {
        const res = await fetch('/api/modules/stealer_parser', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({log: input})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const creds = d.credentials || [];
        const wallets = d.crypto_wallets || [];
        const hvts = d.high_value_targets || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">${d.variant} FORENSIC EXTRACTION</span>
                        <h2 class="card-title" style="color:#C084FC;">${creds.length} CREDENTIAL RECORDS UNCOVERED</h2>
                    </div>
                    <span class="badge ${d.threat_level === 'CRITICAL' ? 'hazard' : 'cyan'}">${d.threat_level}</span>
                </div>
                <div class="card-body">
                    <div class="grid-3col" style="gap:10px; margin-bottom:14px;">
                        <div class="mini-stat-card"><span class="mini-stat-label">TOTAL PASSWORDS</span><span class="mini-stat-val cyan">${creds.length}</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">CRYPTO WALLETS</span><span class="mini-stat-val ${wallets.length > 0 ? 'red' : 'emerald'}">${wallets.length} EXPOSED</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">HVT ACCOUNTS</span><span class="mini-stat-val ${hvts.length > 0 ? 'red' : 'emerald'}">${hvts.length} CRITICAL</span></div>
                    </div>
                    ${wallets.length > 0 ? `
                        <div style="margin-bottom:12px; background:rgba(255,0,85,0.08); border:1px solid rgba(255,0,85,0.3); padding:10px; border-radius:4px;">
                            <span class="hazard mono" style="font-weight:bold; font-size:11px;">COMPROMISED BROWSER CRYPTO WALLETS:</span>
                            <div style="margin-top:6px; display:flex; gap:8px; flex-wrap:wrap;">
                                ${wallets.map(w => `<span class="badge hazard">${escapeHtml(w.wallet)}</span>`).join('')}
                            </div>
                        </div>
                    ` : ''}
                    <div style="max-height:260px; overflow-y:auto; border:1px solid var(--border-slate); border-radius:4px;">
                        <table class="table-tactical" style="width:100%;">
                            <thead><tr><th>URL / HOST</th><th>USERNAME</th><th>PASSWORD</th></tr></thead>
                            <tbody>
                                ${creds.slice(0, 50).map(c => `
                                    <tr>
                                        <td class="cyan mono" style="font-size:11px;">${escapeHtml(c.url)}</td>
                                        <td style="color:#FFF;">${escapeHtml(c.username)}</td>
                                        <td class="mono hazard" style="font-size:11px;">${escapeHtml(c.password)}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">EXTRACTED ${creds.length} CREDENTIALS</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

window.handleStealerFileUpload = function(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function(e) {
        const txt = e.target.result;
        const input = document.getElementById('stealer-raw-input');
        if (input) input.value = txt;
        window.runStealerParser();
    };
    reader.readAsText(file);
};

/* ============================================================
   2. TAB-SHADOWCLONE COMPANION: LINGUISTIC STYLOMETRY ANALYZER
   ============================================================ */
window.runStylometryAnalyzer = async function() {
    const sA = document.getElementById('stylometry-sample-a')?.value || '';
    const sB = document.getElementById('stylometry-sample-b')?.value || '';
    const status = document.getElementById('stylometry-status');
    const results = document.getElementById('stylometry-results');

    if (!sA.trim()) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Enter writing sample A</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> COMPUTING AUTHORSHIP VECTORS...</span>`;
    if (results) results.innerHTML = `<div style="padding:20px; text-align:center;" class="mono cyan">Computing Yule's characteristic K, punctuation profile, and vocabulary overlap...</div>`;

    try {
        const res = await fetch('/api/modules/stylometry_analyzer', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({sample_a: sA, sample_b: sB})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        if (d.mode === 'single_profile') {
            const p = d.profile;
            results.innerHTML = `
                <div class="glass-card" style="margin-top:16px;">
                    <div class="card-header"><h2 class="card-title" style="color:#C084FC;">SINGLE AUTHOR LINGUISTIC PROFILE</h2></div>
                    <div class="card-body">
                        <div class="grid-3col" style="gap:10px; margin-bottom:12px;">
                            <div class="mini-stat-card"><span class="mini-stat-label">TOTAL WORDS</span><span class="mini-stat-val cyan">${p.total_words}</span></div>
                            <div class="mini-stat-card"><span class="mini-stat-label">TYPE-TOKEN RATIO</span><span class="mini-stat-val emerald">${p.type_token_ratio}</span></div>
                            <div class="mini-stat-card"><span class="mini-stat-label">YULE'S K RICHNESS</span><span class="mini-stat-val violet">${p.yules_k}</span></div>
                        </div>
                    </div>
                </div>
            `;
        } else {
            const v = d.cross_vector_analysis || {};
            results.innerHTML = `
                <div class="glass-card" style="margin-top:16px;">
                    <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <span class="telemetry-label">CROSS-SAMPLE AUTHORSHIP ATTRIBUTION</span>
                            <h2 class="card-title" style="color:#C084FC;">ATTRIBUTION CONFIDENCE: ${d.attribution_confidence}</h2>
                        </div>
                        <span class="badge ${d.score_numeric >= 70 ? 'emerald' : (d.score_numeric >= 45 ? 'hazard' : 'cyan')}">${d.verdict}</span>
                    </div>
                    <div class="card-body">
                        <div class="grid-3col" style="gap:10px; margin-bottom:14px;">
                            <div class="mini-stat-card"><span class="mini-stat-label">PUNCTUATION SIMILARITY</span><span class="mini-stat-val cyan">${(v.punctuation_similarity * 100).toFixed(1)}%</span></div>
                            <div class="mini-stat-card"><span class="mini-stat-label">VOCABULARY JACCARD</span><span class="mini-stat-val emerald">${(v.vocabulary_jaccard_overlap * 100).toFixed(1)}%</span></div>
                            <div class="mini-stat-card"><span class="mini-stat-label">TTR LEXICAL DELTA</span><span class="mini-stat-val violet">${v.lexical_richness_delta}</span></div>
                        </div>
                        <div class="mono small-text dim">SHARED SIGNATURE TOKENS: ${v.shared_signature_tokens ? v.shared_signature_tokens.join(', ') : 'None'}</div>
                    </div>
                </div>
            `;
        }
        if (status) status.innerHTML = `<span class="emerald">ATTRIBUTION COMPLETE</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   3. TAB-SPIDER CRAWL COMPANION: PARAM-MINER & OPENAPI FUZZER
   ============================================================ */
window.runParamMiner = async function() {
    const target = document.getElementById('paramminer-target')?.value || '';
    const status = document.getElementById('paramminer-status');
    const results = document.getElementById('paramminer-results');

    if (!target.trim()) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Enter target base URL</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> FUZZING PARAMETERS &amp; SWAGGER PATHS...</span>`;
    if (results) results.innerHTML = `<div style="padding:20px; text-align:center;" class="mono cyan">Probing OpenAPI/Swagger portals and injecting privileged debug query parameters...</div>`;

    try {
        const res = await fetch('/api/modules/param_miner', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target: target})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const apis = d.discovered_apis || [];
        const params = d.param_findings || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">ATTACK SURFACE MAPPING</span>
                        <h2 class="card-title" style="color:#C084FC;">${apis.length} EXPOSED APIS // ${params.length} DEBUG PARAMS</h2>
                    </div>
                    <span class="badge ${d.posture === 'CRITICAL_EXPOSURE' ? 'hazard' : 'emerald'}">${d.posture}</span>
                </div>
                <div class="card-body">
                    <div style="margin-bottom:14px;">
                        <span class="telemetry-label">DISCOVERED OPENAPI / SWAGGER DOCUMENTATION MANIFESTS</span>
                        ${apis.length > 0 ? `
                            <table class="table-tactical" style="width:100%; margin-top:6px;">
                                <thead><tr><th>PATH</th><th>TITLE</th><th>ENDPOINTS</th><th>STATUS</th></tr></thead>
                                <tbody>
                                    ${apis.map(a => `
                                        <tr>
                                            <td><a href="${escapeHtml(a.url)}" target="_blank" class="cyan mono">${escapeHtml(a.path)}</a></td>
                                            <td style="color:#FFF;">${escapeHtml(a.title)}</td>
                                            <td class="emerald mono">${a.endpoints_uncovered}</td>
                                            <td><span class="badge hazard">${a.status}</span></td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        ` : `<div class="mono small-text dim" style="padding:8px 0;">No unauthenticated Swagger or OpenAPI manifests exposed on common routes.</div>`}
                    </div>

                    <div>
                        <span class="telemetry-label">ANOMALOUS DEBUG PARAMETER REFLECTIONS</span>
                        ${params.length > 0 ? `
                            <table class="table-tactical" style="width:100%; margin-top:6px;">
                                <thead><tr><th>PARAMETER</th><th>INJECTED VALUE</th><th>DIFFERENTIAL REASON</th></tr></thead>
                                <tbody>
                                    ${params.map(p => `
                                        <tr>
                                            <td class="hazard mono">${escapeHtml(p.parameter)}</td>
                                            <td class="cyan mono">${escapeHtml(p.injected_value)}</td>
                                            <td style="color:#e0e6ed;">${escapeHtml(p.delta_reason)}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        ` : `<div class="mono small-text dim" style="padding:8px 0;">Zero debug query parameter differentials triggered.</div>`}
                    </div>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">MINING COMPLETE</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   4. TAB-DOC AUTOPSY COMPANION: MALICIOUS OLE/VBA DETONATOR
   ============================================================ */
window.handleDocDetonatorUpload = async function(file) {
    if (!file) return;
    const status = document.getElementById('docdetonator-status');
    const results = document.getElementById('docdetonator-results');

    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> DETONATING DOCUMENT STATIC MATRIX...</span>`;
    if (results) results.innerHTML = `<div style="padding:20px; text-align:center;" class="mono cyan">Analyzing PDF objects, deobfuscating VBA Chr() chains, and inspecting suspicious Windows APIs...</div>`;

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch('/api/doc_detonator/upload', {
            method: 'POST',
            body: formData
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const vectors = d.pdf_attack_vectors || [];
        const apis = d.suspicious_apis || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">${d.document_type}</span>
                        <h2 class="card-title" style="color:#C084FC;">STATIC WEAPONIZATION AUDIT // ${d.filename}</h2>
                    </div>
                    <span class="badge ${d.risk_score >= 50 ? 'hazard' : 'emerald'}">${d.verdict} (RISK: ${d.risk_score}/100)</span>
                </div>
                <div class="card-body">
                    <div class="grid-3col" style="gap:10px; margin-bottom:14px;">
                        <div class="mini-stat-card"><span class="mini-stat-label">FILE SIZE</span><span class="mini-stat-val cyan">${(d.file_size/1024).toFixed(1)} KB</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">ENTROPY</span><span class="mini-stat-val ${d.overall_entropy > 7.2 ? 'red' : 'cyan'}">${d.overall_entropy} / 8.0</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">SUSPICIOUS APIS</span><span class="mini-stat-val ${apis.length > 0 ? 'red' : 'emerald'}">${apis.length} DETECTED</span></div>
                    </div>

                    ${vectors.length > 0 ? `
                        <div style="margin-bottom:12px;">
                            <span class="telemetry-label">PDF ATTACK &amp; AUTO-EXECUTION VECTORS</span>
                            <table class="table-tactical" style="width:100%; margin-top:6px;">
                                <thead><tr><th>TAG</th><th>COUNT</th><th>DESCRIPTION</th></tr></thead>
                                <tbody>
                                    ${vectors.map(v => `
                                        <tr>
                                            <td class="hazard mono">${escapeHtml(v.tag)}</td>
                                            <td class="cyan mono">${v.occurrences}</td>
                                            <td style="color:#e0e6ed;">${escapeHtml(v.description)}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    ` : ''}

                    ${apis.length > 0 ? `
                        <div>
                            <span class="telemetry-label">SUSPICIOUS WIN32 / PROCESS MEMORY APIS</span>
                            <table class="table-tactical" style="width:100%; margin-top:6px;">
                                <thead><tr><th>API</th><th>COUNT</th><th>IMPLICATION</th></tr></thead>
                                <tbody>
                                    ${apis.map(a => `
                                        <tr>
                                            <td class="hazard mono">${escapeHtml(a.api)}</td>
                                            <td class="cyan mono">${a.occurrences}</td>
                                            <td style="color:#e0e6ed;">${escapeHtml(a.description)}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">DETONATION AUDIT COMPLETE</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   5. TAB-VOICE PRINT COMPANION: ENF ELECTRIC GRID GEOLOCATOR
   ============================================================ */
window.handleEnfAnalyzerUpload = async function(file) {
    if (!file) return;
    const status = document.getElementById('enfanalyzer-status');
    const results = document.getElementById('enfanalyzer-results');

    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> PROBING 50HZ/60HZ ENF HUM &amp; REVERBERATION...</span>`;
    if (results) results.innerHTML = `<div style="padding:20px; text-align:center;" class="mono cyan">Analyzing electromagnetic power grid harmonics and RT60 acoustic decay...</div>`;

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch('/api/enf_analyzer/upload', {
            method: 'POST',
            body: formData
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">ELECTROMAGNETIC ENF SIGNATURE &amp; ROOM GEOLOCATION</span>
                        <h2 class="card-title" style="color:#C084FC;">${d.detected_grid}</h2>
                    </div>
                    <span class="badge cyan">${d.grid_attribution_confidence} CONFIDENCE</span>
                </div>
                <div class="card-body">
                    <div class="grid-3col" style="gap:10px; margin-bottom:14px;">
                        <div class="mini-stat-card"><span class="mini-stat-label">NOMINAL MAINS FREQ</span><span class="mini-stat-val cyan">${d.measured_nominal_freq} Hz</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">ESTIMATED RT60 DECAY</span><span class="mini-stat-val emerald">${d.room_acoustics?.estimated_rt60_seconds}s</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">AUDIO DURATION</span><span class="mini-stat-val violet">${d.duration_sec}s</span></div>
                    </div>
                    <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-slate); padding:12px; border-radius:4px;">
                        <div class="small-text mono cyan" style="margin-bottom:6px;">ACOUSTIC ENVIRONMENT ATTRIBUTION:</div>
                        <div style="color:#FFF; font-weight:600; font-size:13px; margin-bottom:4px;">${escapeHtml(d.room_acoustics?.inferred_physical_environment)}</div>
                        <div class="small-text dim">${escapeHtml(d.forensic_summary)}</div>
                    </div>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">ENF AUDIT COMPLETE</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   6. TAB-ORBITAL EYE COMPANION: CELESTIAL STAR SOLVER
   ============================================================ */
window.runStarSolver = async function() {
    const consts = (document.getElementById('starsolver-constellations')?.value || '').split(',').map(s => s.trim()).filter(Boolean);
    const polarisVal = document.getElementById('starsolver-polaris')?.value;
    const polaris = polarisVal ? parseFloat(polarisVal) : null;
    const crux = document.getElementById('starsolver-crux')?.checked || false;
    const date = document.getElementById('starsolver-date')?.value || '';
    const status = document.getElementById('starsolver-status');
    const results = document.getElementById('starsolver-results');

    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> SOLVING CELESTIAL COORDINATES...</span>`;
    if (results) results.innerHTML = `<div style="padding:20px; text-align:center;" class="mono cyan">Calculating Polaris altitude vector, moon illumination phase, and seasonal constellation declinations...</div>`;

    try {
        const res = await fetch('/api/modules/star_solver', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({constellations: consts, polaris_alt: polaris, crux: crux, date: date})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const moon = d.moon_phase_telemetry || {};
        const stars = d.matched_celestial_landmarks || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">ASTRO-GEOLOCATION SOLUTION</span>
                        <h2 class="card-title" style="color:#C084FC;">ESTIMATED LATITUDE: ${d.estimated_latitude}° (${d.hemisphere})</h2>
                    </div>
                    <span class="badge cyan">${d.geonav_confidence}</span>
                </div>
                <div class="card-body">
                    <div class="grid-3col" style="gap:10px; margin-bottom:14px;">
                        <div class="mini-stat-card"><span class="mini-stat-label">LATITUDE BRACKET</span><span class="mini-stat-val cyan">${d.latitude_bracket}</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">LUNAR PHASE</span><span class="mini-stat-val emerald">${moon.lunar_phase}</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">MOON ILLUMINATION</span><span class="mini-stat-val violet">${moon.illumination_percentage}</span></div>
                    </div>
                    <table class="table-tactical" style="width:100%;">
                        <thead><tr><th>CONSTELLATION</th><th>DECLINATION</th><th>PEAK SEASON</th></tr></thead>
                        <tbody>
                            ${stars.map(s => `<tr><td class="cyan mono">${escapeHtml(s.name)}</td><td class="mono">${escapeHtml(s.declination)}</td><td class="dim">${escapeHtml(s.optimal_season)}</td></tr>`).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">SOLVED</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   7. TAB-EVMSOL COMPANION: DEX LIQUIDITY & FLASH-LOAN MEV TRACER
   ============================================================ */
window.runDexArbitrage = async function() {
    const input = document.getElementById('dex-input')?.value || '';
    const chain = document.getElementById('dex-chain')?.value || '1';
    const status = document.getElementById('dexarbitrage-status');
    const results = document.getElementById('dexarbitrage-results');

    if (!input.trim()) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Enter EVM tx hash or pool address</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> TRACING MEMPOOL &amp; DEX ROUTING...</span>`;
    if (results) results.innerHTML = `<div style="padding:20px; text-align:center;" class="mono cyan">Auditing Uniswap V2/V3 bytecode, detecting Aave/Balancer flash-loans, and analyzing sandwich priority bribes...</div>`;

    try {
        const res = await fetch('/api/modules/dex_arbitrage', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target: input, chain: chain})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        if (d.mode === 'TRANSACTION_TRACE') {
            const fl = d.flash_loan_telemetry || {};
            const mev = d.mev_heuristics || {};
            results.innerHTML = `
                <div class="glass-card" style="margin-top:16px;">
                    <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <span class="telemetry-label">TRANSACTION EXECUTION TRACE</span>
                            <h2 class="card-title" style="color:#C084FC;">${d.router_identity}</h2>
                        </div>
                        <span class="badge ${fl.detected ? 'hazard' : 'cyan'}">${fl.detected ? 'FLASH-LOAN INVOLVED' : 'STANDARD SWAP'}</span>
                    </div>
                    <div class="card-body">
                        <div class="grid-3col" style="gap:10px; margin-bottom:14px;">
                            <div class="mini-stat-card"><span class="mini-stat-label">TRANSFER VALUE</span><span class="mini-stat-val cyan">${d.value_native}</span></div>
                            <div class="mini-stat-card"><span class="mini-stat-label">GAS PRICE</span><span class="mini-stat-val emerald">${d.gas_price_gwei} Gwei</span></div>
                            <div class="mini-stat-card"><span class="mini-stat-label">SANDWICH RISK</span><span class="mini-stat-val ${mev.frontrun_sandwich_indicator === 'HIGH' ? 'red' : 'emerald'}">${mev.frontrun_sandwich_indicator}</span></div>
                        </div>
                        <div class="small-text mono dim">BLOCK: ${d.block_number} | SENDER: ${d.sender} | DESTINATION: ${d.destination_contract}</div>
                    </div>
                </div>
            `;
        } else {
            const amm = d.uniswap_pair_conformance || {};
            results.innerHTML = `
                <div class="glass-card" style="margin-top:16px;">
                    <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <span class="telemetry-label">AMM POOL CONTRACT AUDIT</span>
                            <h2 class="card-title" style="color:#C084FC;">${amm.liquidity_classification}</h2>
                        </div>
                        <span class="badge emerald">BYTECODE VERIFIED</span>
                    </div>
                    <div class="card-body">
                        <div class="grid-2col" style="gap:10px;">
                            <div class="mini-stat-card"><span class="mini-stat-label">SYNC() SELECTOR</span><span class="mini-stat-val ${amm.implements_sync ? 'emerald' : 'red'}">${amm.implements_sync ? 'CONFIRMED' : 'ABSENT'}</span></div>
                            <div class="mini-stat-card"><span class="mini-stat-label">SWAP() SELECTOR</span><span class="mini-stat-val ${amm.implements_swap ? 'emerald' : 'red'}">${amm.implements_swap ? 'CONFIRMED' : 'ABSENT'}</span></div>
                        </div>
                    </div>
                </div>
            `;
        }
        if (status) status.innerHTML = `<span class="emerald">TRACE COMPLETE</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   8. TAB-SHADOW AI COMPANION: MODEL INVERSION & MEMORIZATION
   ============================================================ */
window.runModelInversion = async function() {
    const text = document.getElementById('modelinversion-input')?.value || '';
    const status = document.getElementById('modelinversion-status');
    const results = document.getElementById('modelinversion-results');

    if (!text.trim()) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Enter completion or response text</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> PROBING MODEL INVERSION RESISTANCE...</span>`;
    if (results) results.innerHTML = `<div style="padding:20px; text-align:center;" class="mono cyan">Auditing for canary regurgitation, PII extraction, and internal credential memorization...</div>`;

    try {
        const res = await fetch('/api/modules/model_inversion', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({prompt: text})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const leaks = d.detected_leaks || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">TRAINING DATA PRIVACY EVALUATION</span>
                        <h2 class="card-title" style="color:#C084FC;">${d.verdict}</h2>
                    </div>
                    <span class="badge ${d.memorization_risk_score >= 50 ? 'hazard' : 'emerald'}">RISK: ${d.memorization_risk_score}/100</span>
                </div>
                <div class="card-body">
                    ${leaks.length > 0 ? `
                        <table class="table-tactical" style="width:100%; margin-bottom:12px;">
                            <thead><tr><th>PROBE CATEGORY</th><th>OCCURRENCES</th><th>SAMPLE LEAK</th></tr></thead>
                            <tbody>
                                ${leaks.map(l => `
                                    <tr>
                                        <td class="hazard mono">${escapeHtml(l.category)}</td>
                                        <td class="cyan mono">${l.matches_count}</td>
                                        <td class="mono emerald" style="font-size:11px;">${escapeHtml(l.leaked_sample)}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    ` : `<div class="mono small-text emerald" style="margin-bottom:12px;">Zero memorized canary strings, private keys, or PII regex patterns detected in sample.</div>`}

                    <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-slate); padding:10px; border-radius:4px;">
                        <span class="telemetry-label">RECOMMENDED PRIVACY HARDENING:</span>
                        <ul style="margin:6px 0 0 16px; padding:0; font-size:11px; color:#e0e6ed;">
                            ${(d.recommended_hardening || []).map(r => `<li>${escapeHtml(r)}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">INVERSION AUDIT COMPLETE</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   9. TAB-TELEMETRY COMPANION: FAVICON MURMUR3 & JARM CLUSTERER
   ============================================================ */
window.runJarmClusterer = async function() {
    const target = document.getElementById('jarm-input')?.value || '';
    const status = document.getElementById('jarmclusterer-status');
    const results = document.getElementById('jarmclusterer-results');

    if (!target.trim()) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Enter target host</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> HASHING FAVICON &amp; PROBING TLS CIPHERS...</span>`;
    if (results) results.innerHTML = `<div style="padding:20px; text-align:center;" class="mono cyan">Computing MurmurHash3 favicon signature and SSL leaf certificate fingerprints...</div>`;

    try {
        const res = await fetch('/api/modules/jarm_clusterer', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target: target})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const fav = d.favicon_telemetry || {};
        const tls = d.tls_telemetry || {};
        const q = d.recon_queries || {};

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">ORIGIN IP DE-CLOAKING</span>
                        <h2 class="card-title" style="color:#C084FC;">MURMUR3: ${fav.murmur3_hash !== null ? fav.murmur3_hash : 'UNAVAILABLE'}</h2>
                    </div>
                    <span class="badge cyan">${d.origin_deconfliction}</span>
                </div>
                <div class="card-body">
                    <div class="grid-2col" style="gap:10px; margin-bottom:14px;">
                        <div class="mini-stat-card"><span class="mini-stat-label">NEGOTIATED TLS VERSION</span><span class="mini-stat-val emerald">${tls.tls_version || 'N/A'}</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">CIPHER SUITE</span><span class="mini-stat-val cyan" style="font-size:12px;">${tls.cipher_suite || 'N/A'}</span></div>
                    </div>
                    <div style="background:#070d18; border:1px solid var(--border-slate); padding:12px; border-radius:4px; font-family:monospace; font-size:11px;">
                        <div class="telemetry-label" style="margin-bottom:8px;">TACTICAL RECON SEARCH QUERIES (DE-CLOAK ORIGIN):</div>
                        <div style="margin-bottom:6px;"><span class="cyan">SHODAN:</span> <span style="color:#FFF;">${escapeHtml(q.shodan_query)}</span></div>
                        <div><span class="cyan">CENSYS:</span> <span style="color:#FFF;">${escapeHtml(q.censys_query)}</span></div>
                    </div>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">HASHED</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   10. TAB-RANSOM COMPANION: EXTORTION NEGOTIATION CATALOG
   ============================================================ */
window.runRansomNegotiator = async function() {
    const q = document.getElementById('ransom-search-input')?.value || '';
    const status = document.getElementById('ransomnegotiator-status');
    const results = document.getElementById('ransomnegotiator-results');

    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> SEARCHING EXTORTION NEGOTIATIONS...</span>`;

    try {
        const res = await fetch('/api/modules/ransom_negotiator', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target: q})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const list = d.results || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">NEGOTIATION INTELLIGENCE DATABASE</span>
                        <h2 class="card-title" style="color:#C084FC;">${list.length} CARTELS &amp; DECRYPTOR PROFILES MATCHED</h2>
                    </div>
                    <span class="badge violet">NOMORERANSOM / IC3</span>
                </div>
                <div class="card-body">
                    <table class="table-tactical" style="width:100%; margin-bottom:14px;">
                        <thead><tr><th>RANSOMWARE FAMILY</th><th>AVG RANSOM</th><th>TYPICAL DISCOUNT</th><th>DECRYPTOR AVAILABILITY</th></tr></thead>
                        <tbody>
                            ${list.map(r => `
                                <tr>
                                    <td><strong style="color:#FFF;">${escapeHtml(r.family)}</strong> <span class="dim">(${escapeHtml(r.extension)})</span><div class="small-text dim" style="margin-top:2px;">${escapeHtml(r.negotiation_tactic)}</div></td>
                                    <td class="cyan mono">${escapeHtml(r.avg_ransom_usd)}</td>
                                    <td class="emerald mono">${escapeHtml(r.typical_discount)}</td>
                                    <td><span class="badge ${r.decryptor_available ? 'emerald' : 'hazard'}">${r.decryptor_available ? 'FREE DECRYPTOR' : 'NO DECRYPTOR'}</span><div class="small-text mono cyan" style="font-size:10px; margin-top:4px;">${escapeHtml(r.decryptor_tool)}</div></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">MATCHED ${list.length} RECORDS</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   11. TAB-CAM VECTOR COMPANION: SCADA / ICS RADAR
   ============================================================ */
window.runScadaRadar = async function() {
    const target = document.getElementById('scada-input')?.value || '';
    const status = document.getElementById('scadaradar-status');
    const results = document.getElementById('scadaradar-results');

    if (!target.trim()) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Enter target host</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> PROBING MODBUS, S7, BACNET, MQTT...</span>`;
    if (results) results.innerHTML = `<div style="padding:20px; text-align:center;" class="mono cyan">Scanning industrial control ports (502, 102, 47808, 1883) and mapping Purdue model levels...</div>`;

    try {
        const res = await fetch('/api/modules/scada_radar', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target: target})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const openPorts = d.exposed_industrial_controllers || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">OPERATIONAL TECHNOLOGY (OT) PERIMETER AUDIT</span>
                        <h2 class="card-title" style="color:#C084FC;">${openPorts.length} INDUSTRIAL CONTROLLERS DETECTED</h2>
                    </div>
                    <span class="badge ${openPorts.length > 0 ? 'hazard' : 'emerald'}">${d.posture_assessment}</span>
                </div>
                <div class="card-body">
                    ${openPorts.length > 0 ? `
                        <table class="table-tactical" style="width:100%; margin-bottom:14px;">
                            <thead><tr><th>PORT</th><th>PROTOCOL</th><th>PURDUE LEVEL</th><th>IDENTIFIED HARDWARE</th></tr></thead>
                            <tbody>
                                ${openPorts.map(p => `
                                    <tr>
                                        <td class="hazard mono">${p.port}</td>
                                        <td class="cyan mono">${escapeHtml(p.protocol)}</td>
                                        <td class="violet mono">${escapeHtml(p.purdue_level)}</td>
                                        <td style="color:#FFF;">${escapeHtml(p.identified_hardware)}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    ` : `<div class="mono small-text emerald" style="margin-bottom:12px;">Target perimeter is hardened. Zero exposed SCADA/ICS/PLC ports responding to active handshake probes.</div>`}
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">SCADA AUDIT COMPLETE</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   12. TAB-CANARY COMPANION: TRIPWIRE DECOY VAULT
   ============================================================ */
window.runTripwireVault = async function() {
    const type = document.getElementById('tripwire-type')?.value || 'sql';
    const label = document.getElementById('tripwire-label')?.value || 'SEC_CORP_VAULT';
    const status = document.getElementById('tripwirevault-status');
    const results = document.getElementById('tripwirevault-results');

    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> FABRICATING HONEYTOKEN ASSET...</span>`;

    try {
        const res = await fetch('/api/modules/tripwire_vault', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({type: type, label: label})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">WEAPONIZED DECEPTION DECOY</span>
                        <h2 class="card-title" style="color:#C084FC;">${d.filename}</h2>
                    </div>
                    <span class="badge emerald">CANARY ARMED</span>
                </div>
                <div class="card-body">
                    <div style="margin-bottom:10px;" class="small-text cyan mono">LISTENER FQDN: ${d.canary_listener_fqdn}</div>
                    <div class="form-group">
                        <textarea class="input-tactical mono" rows="8" readonly style="font-size:11px; color:#00F0FF; background:#070d18;">${escapeHtml(d.decoy_content)}</textarea>
                    </div>
                    <button class="btn-tactical-xs cyan" onclick="navigator.clipboard.writeText(this.previousElementSibling.firstElementChild.value); alert('Decoy asset copied to clipboard');">COPY DECOY BUFFER</button>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">DECOY ARMED</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   13. TAB-PROFILER COMPANION: PERSONA SYNTHESIZER & DOSSIER
   ============================================================ */
window.runPersonaSynthesizer = async function() {
    const target = document.getElementById('persona-target')?.value || '';
    const notes = document.getElementById('persona-notes')?.value || '';
    const status = document.getElementById('personasynthesizer-status');
    const results = document.getElementById('personasynthesizer-results');

    if (!target.trim()) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Enter target persona identifier</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> SYNTHESIZING TIMELINE &amp; DOSSIER...</span>`;

    try {
        const res = await fetch('/api/modules/persona_synthesizer', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target: target, notes: notes})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const timeline = d.chronological_evolution || [];
        const mutations = d.heuristic_alias_mutations || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">${d.dossier_id}</span>
                        <h2 class="card-title" style="color:#C084FC;">${d.primary_handle} // UNIFIED DOSSIER</h2>
                    </div>
                    <span class="badge cyan">${d.opsec_hygiene_score}</span>
                </div>
                <div class="card-body">
                    <div style="margin-bottom:14px;">
                        <span class="telemetry-label">CHRONOLOGICAL DIGITAL EVOLUTION TIMELINE</span>
                        ${timeline.map(t => `
                            <div style="padding:8px 12px; background:rgba(255,255,255,0.02); border-left:2px solid #00F0FF; margin-bottom:6px;">
                                <div class="cyan mono" style="font-size:11px; font-weight:bold;">${escapeHtml(t.era)}</div>
                                <div class="small-text dim">${escapeHtml(t.milestone)}</div>
                            </div>
                        `).join('')}
                    </div>
                    <div style="margin-bottom:12px;">
                        <span class="telemetry-label">HEURISTIC ALIAS PERMUTATIONS:</span>
                        <div style="display:flex; gap:6px; flex-wrap:wrap; margin-top:4px;">
                            ${mutations.map(m => `<span class="badge cyan mono">${escapeHtml(m)}</span>`).join('')}
                        </div>
                    </div>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">DOSSIER READY</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   14. TAB-BREACH COMPANION: LOCAL COMBO-LIST DE-HASHER
   ============================================================ */
window.runHashCracker = async function() {
    const input = document.getElementById('hashcracker-input')?.value || '';
    const status = document.getElementById('hashcracker-status');
    const results = document.getElementById('hashcracker-results');

    if (!input.trim()) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Enter hash string</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> IDENTIFYING &amp; DE-HASHING...</span>`;

    try {
        const res = await fetch('/api/modules/hash_cracker', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target: input})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const algos = d.detected_algorithms || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">${d.matched_algorithm}</span>
                        <h2 class="card-title" style="color:#C084FC;">${d.cracked ? `RECOVERED: ${escapeHtml(d.plaintext)}` : 'HASH IDENTIFIED'}</h2>
                    </div>
                    <span class="badge ${d.cracked ? 'emerald' : 'hazard'}">${d.cracked ? 'CRACKED' : 'UNCRACKED'}</span>
                </div>
                <div class="card-body">
                    <div style="margin-bottom:12px;">
                        <span class="telemetry-label">CANDIDATE ALGORITHMS &amp; HASHCAT MODES</span>
                        <table class="table-tactical" style="width:100%; margin-top:6px;">
                            <thead><tr><th>ALGORITHM</th><th>HASHCAT MODE</th><th>STRENGTH</th></tr></thead>
                            <tbody>
                                ${algos.map(a => `<tr><td class="cyan mono">${escapeHtml(a.algorithm)}</td><td class="mono">-m ${a.hashcat_mode}</td><td><span class="badge ${a.strength === 'BROKEN' ? 'hazard' : 'emerald'}">${a.strength}</span></td></tr>`).join('')}
                            </tbody>
                        </table>
                    </div>
                    ${d.complexity_audit ? `
                        <div class="grid-3col" style="gap:8px;">
                            <div class="mini-stat-card"><span class="mini-stat-label">MASK PATTERN</span><span class="mini-stat-val cyan mono">${d.complexity_audit.mask_pattern}</span></div>
                            <div class="mini-stat-card"><span class="mini-stat-label">ENTROPY BITS</span><span class="mini-stat-val emerald">${d.complexity_audit.entropy_bits} bits</span></div>
                            <div class="mini-stat-card"><span class="mini-stat-label">LENGTH</span><span class="mini-stat-val violet">${d.complexity_audit.length} chars</span></div>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">PROCESSED</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   15. TAB-FOOTPRINT COMPANION: CARRIER HLR & SIM-SWAP AUDITOR
   ============================================================ */
window.runHlrAnalyzer = async function() {
    const phone = document.getElementById('hlr-input')?.value || '';
    const status = document.getElementById('hlranalyzer-status');
    const results = document.getElementById('hlranalyzer-results');

    if (!phone.trim()) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Enter phone number</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> AUDITING CARRIER ROUTING &amp; SIM-SWAP...</span>`;

    try {
        const res = await fetch('/api/modules/hlr_analyzer', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target: phone})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const hlr = d.hlr_routing_telemetry || {};

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">${d.destination_country} (${d.country_calling_code})</span>
                        <h2 class="card-title" style="color:#C084FC;">${d.formatted_e164}</h2>
                    </div>
                    <span class="badge ${hlr.sim_swap_exposure_level === 'HIGH_VULNERABILITY' ? 'hazard' : 'emerald'}">${hlr.sim_swap_exposure_level}</span>
                </div>
                <div class="card-body">
                    <div class="grid-3col" style="gap:10px; margin-bottom:14px;">
                        <div class="mini-stat-card"><span class="mini-stat-label">LINE TYPE</span><span class="mini-stat-val cyan">${d.detected_line_type}</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">NETWORK STATUS</span><span class="mini-stat-val emerald">${hlr.network_status}</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">ROAMING</span><span class="mini-stat-val violet">${hlr.roaming_status}</span></div>
                    </div>
                    <div class="small-text dim" style="margin-bottom:8px;">MAJOR CELLULAR OPERATORS (MCC/MNC):</div>
                    <div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:12px;">
                        ${(d.primary_carriers_mcc_mnc || []).map(c => `<span class="badge cyan mono">${escapeHtml(c)}</span>`).join('')}
                    </div>
                    <div class="small-text dim">${escapeHtml(d.opsec_implication)}</div>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">HLR AUDIT COMPLETE</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   16. TAB-MAIL TRACER COMPANION: RAW RFC 822 HEADER INFILTRATOR
   ============================================================ */
window.runEmailHeaderAnalyzer = async function() {
    const headers = document.getElementById('emailheader-input')?.value || '';
    const status = document.getElementById('emailheader-status');
    const results = document.getElementById('emailheader-results');

    if (!headers.trim()) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Paste email headers</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> RECONSTRUCTING TRANSIT HOPS...</span>`;

    try {
        const res = await fetch('/api/modules/email_header_analyzer', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({headers: headers})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const auth = d.authentication_verdict || {};
        const hops = d.transit_route || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">ORIGINATING CLIENT IP: ${d.originating_client_ip}</span>
                        <h2 class="card-title" style="color:#C084FC;">${escapeHtml(d.subject)}</h2>
                    </div>
                    <span class="badge ${d.spoofing_risk_score >= 40 ? 'hazard' : 'emerald'}">${d.verdict}</span>
                </div>
                <div class="card-body">
                    <div class="grid-3col" style="gap:10px; margin-bottom:14px;">
                        <div class="mini-stat-card"><span class="mini-stat-label">SPF AUTH</span><span class="mini-stat-val ${auth.spf === 'PASS' ? 'emerald' : 'red'}">${auth.spf}</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">DKIM SIGNATURE</span><span class="mini-stat-val ${auth.dkim === 'PASS' ? 'emerald' : 'red'}">${auth.dkim}</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">TRANSIT HOPS</span><span class="mini-stat-val cyan">${d.transit_hops_count} HOPS</span></div>
                    </div>
                    <div style="max-height:220px; overflow-y:auto; border:1px solid var(--border-slate); border-radius:4px;">
                        <table class="table-tactical" style="width:100%;">
                            <thead><tr><th>HOP</th><th>RECEIVED HEADER SNIPPET</th><th>DETECTED IPS</th></tr></thead>
                            <tbody>
                                ${hops.map(h => `
                                    <tr>
                                        <td class="cyan mono">#${h.hop_number}</td>
                                        <td class="small-text dim">${escapeHtml(h.raw_received)}</td>
                                        <td class="mono hazard" style="font-size:10px;">${(h.detected_ips || []).join(', ')}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">INFILTRATION COMPLETE</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   17. TAB-CODE HUNTER COMPANION: GITLEAKS SECRET SCANNER
   ============================================================ */
window.runGitleaksScanner = async function() {
    const code = document.getElementById('gitleaks-input')?.value || '';
    const status = document.getElementById('gitleaks-status');
    const results = document.getElementById('gitleaks-results');

    if (!code.trim()) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Paste code snippet</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> SCANNING CODE DIFF FOR SECRETS...</span>`;

    try {
        const res = await fetch('/api/modules/gitleaks_scanner', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({code: code})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const findings = d.findings || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">GITLEAKS FORENSIC ENGINE</span>
                        <h2 class="card-title" style="color:#C084FC;">${findings.length} EXPOSED SECRETS IDENTIFIED</h2>
                    </div>
                    <span class="badge ${findings.length > 0 ? 'hazard' : 'emerald'}">${d.threat_tier}</span>
                </div>
                <div class="card-body">
                    ${findings.length > 0 ? `
                        <table class="table-tactical" style="width:100%; margin-bottom:12px;">
                            <thead><tr><th>RULE / ASSET</th><th>SEVERITY</th><th>MASKED SECRET</th><th>SNIPPET CONTEXT</th></tr></thead>
                            <tbody>
                                ${findings.map(f => `
                                    <tr>
                                        <td><strong style="color:#FFF;">${escapeHtml(f.rule_name)}</strong><div class="small-text dim">${escapeHtml(f.category)}</div></td>
                                        <td><span class="badge ${f.severity === 'CRITICAL' ? 'hazard' : 'cyan'}">${f.severity}</span></td>
                                        <td class="mono hazard">${escapeHtml(f.masked_secret)}</td>
                                        <td class="small-text mono dim">${escapeHtml(f.snippet_context)}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    ` : `<div class="mono small-text emerald">Zero hardcoded cloud credentials, tokens, or private keys uncovered in buffer.</div>`}
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">SCAN COMPLETE</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   18. TAB-DEEP IDENTITY COMPANION: 1:1 BIOMETRIC FACE MATCHER
   ============================================================ */
window.runFaceMatcher = async function() {
    const fileA = document.getElementById('facematch-file-a')?.files[0];
    const fileB = document.getElementById('facematch-file-b')?.files[0];
    const status = document.getElementById('facematcher-status');
    const results = document.getElementById('facematcher-results');

    if (!fileA || !fileB) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Select two portrait images</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> COMPUTING 128D VECTOR COSINE SIMILARITY...</span>`;

    const formData = new FormData();
    formData.append('file_a', fileA);
    formData.append('file_b', fileB);

    try {
        const res = await fetch('/api/face_matcher/upload', {
            method: 'POST',
            body: formData
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const geo = d.geometric_landmarks || {};

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">1:1 BIOMETRIC FACIAL VERIFICATION</span>
                        <h2 class="card-title" style="color:#C084FC;">SIMILARITY: ${d.biometric_similarity}</h2>
                    </div>
                    <span class="badge ${d.cosine_score >= 0.75 ? 'emerald' : 'hazard'}">${d.match_confidence}</span>
                </div>
                <div class="card-body">
                    <div class="grid-3col" style="gap:10px; margin-bottom:14px;">
                        <div class="mini-stat-card"><span class="mini-stat-label">COSINE COEFFICIENT</span><span class="mini-stat-val cyan">${d.cosine_score}</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">IMAGE A RATIO</span><span class="mini-stat-val emerald">${geo.image_a_interpupillary_ratio}</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">LANDMARK DELTA</span><span class="mini-stat-val violet">${geo.landmark_ratio_delta}</span></div>
                    </div>
                    <div class="small-text dim">${escapeHtml(d.forensic_conclusion)}</div>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">COMPARISON COMPLETE</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   19. TAB-DOMAIN ORACLE COMPANION: SUBDOMAIN TAKEOVER AUDITOR
   ============================================================ */
window.runTakeoverAuditor = async function() {
    const domain = document.getElementById('takeover-domain')?.value || '';
    const status = document.getElementById('takeover-status');
    const results = document.getElementById('takeover-results');

    if (!domain.trim()) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Enter domain</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> PROBING AXFR &amp; DANGLING CLOUD CNAME TARGETS...</span>`;

    try {
        const res = await fetch('/api/modules/takeover_auditor', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target: domain})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const candidates = d.takeover_candidates || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">CNAME RECORD: ${d.cname_target}</span>
                        <h2 class="card-title" style="color:#C084FC;">${d.domain}</h2>
                    </div>
                    <span class="badge ${d.overall_posture.includes('CRITICAL') ? 'hazard' : 'emerald'}">${d.overall_posture}</span>
                </div>
                <div class="card-body">
                    <div class="small-text cyan mono" style="margin-bottom:10px;">ZONE TRANSFER: ${d.axfr_zone_transfer_test}</div>
                    ${candidates.length > 0 ? `
                        <table class="table-tactical" style="width:100%;">
                            <thead><tr><th>CLOUD PROVIDER</th><th>CNAME POINTER</th><th>EXPLOITATION STATUS</th></tr></thead>
                            <tbody>
                                ${candidates.map(c => `
                                    <tr>
                                        <td class="hazard mono">${escapeHtml(c.service)}</td>
                                        <td class="cyan mono">${escapeHtml(c.cname_pointer)}</td>
                                        <td><span class="badge ${c.vulnerable_to_claim ? 'hazard' : 'emerald'}">${c.severity}</span></td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    ` : `<div class="mono small-text emerald">Zero dangling CNAME records matched against known cloud providers (S3, GitHub Pages, Heroku, Shopify).</div>`}
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">TAKEOVER AUDIT COMPLETE</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   20. TAB-NETWORK MAPPER COMPANION: SSL/TLS CIPHER SUITE AUDITOR
   ============================================================ */
window.runTlsAuditor = async function() {
    const host = document.getElementById('tls-host')?.value || '';
    const port = document.getElementById('tls-port')?.value || 443;
    const status = document.getElementById('tlsauditor-status');
    const results = document.getElementById('tlsauditor-results');

    if (!host.trim()) {
        if (status) status.innerHTML = `<span class="critical">ERROR: Enter target host</span>`;
        return;
    }
    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> EVALUATING CIPHER SUITES &amp; TLS VERSIONS...</span>`;

    try {
        const res = await fetch('/api/modules/tls_auditor', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target: host, port: parseInt(port, 10)})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const sess = d.negotiated_session || {};
        const protos = d.protocol_matrix || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">CRYPTOGRAPHIC HANDSHAKE EVALUATION</span>
                        <h2 class="card-title" style="color:#C084FC;">${d.target}:${d.port}</h2>
                    </div>
                    <span class="badge emerald">GRADE: ${d.overall_cryptographic_grade}</span>
                </div>
                <div class="card-body">
                    <div class="grid-3col" style="gap:10px; margin-bottom:14px;">
                        <div class="mini-stat-card"><span class="mini-stat-label">TLS PROTOCOL</span><span class="mini-stat-val emerald">${sess.tls_version}</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">FORWARD SECRECY</span><span class="mini-stat-val cyan">${sess.forward_secrecy}</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">KEY BITS</span><span class="mini-stat-val violet">${sess.key_bits} bits</span></div>
                    </div>
                    <div style="margin-bottom:12px;">
                        <span class="telemetry-label">NEGOTIATED CIPHER:</span>
                        <div class="cyan mono" style="font-size:12px;">${sess.negotiated_cipher}</div>
                    </div>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">TLS AUDIT COMPLETE</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   21. TAB-GEOINT COMPANION: MGRS MILITARY GRID & SATELLITE PASSES
   ============================================================ */
window.runMgrsTracker = async function() {
    const lat = parseFloat(document.getElementById('mgrs-lat')?.value || '48.8584');
    const lon = parseFloat(document.getElementById('mgrs-lon')?.value || '2.2945');
    const status = document.getElementById('mgrstracker-status');
    const results = document.getElementById('mgrstracker-results');

    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> CALCULATING MGRS &amp; SATELLITE EPHEMERIS...</span>`;

    try {
        const res = await fetch('/api/modules/mgrs_tracker', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({lat: lat, lon: lon})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const sun = d.solar_geometry || {};
        const sats = d.upcoming_satellite_overpasses || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">MGRS PRECISION TARGET GRID</span>
                        <h2 class="card-title" style="color:#C084FC;">${d.military_grid_mgrs}</h2>
                    </div>
                    <span class="badge cyan">MAIDENHEAD: ${d.maidenhead_locator}</span>
                </div>
                <div class="card-body">
                    <div class="grid-3col" style="gap:10px; margin-bottom:14px;">
                        <div class="mini-stat-card"><span class="mini-stat-label">SUN ELEVATION</span><span class="mini-stat-val cyan">${sun.solar_elevation_degrees}°</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">SUN AZIMUTH</span><span class="mini-stat-val emerald">${sun.solar_azimuth_degrees}°</span></div>
                        <div class="mini-stat-card"><span class="mini-stat-label">SHADOW MULTIPLIER</span><span class="mini-stat-val violet">${sun.shadow_ratio_multiplier}x</span></div>
                    </div>
                    <table class="table-tactical" style="width:100%;">
                        <thead><tr><th>SATELLITE</th><th>SENSOR TYPE</th><th>NEXT OVERPASS WINDOW</th><th>RESOLUTION</th></tr></thead>
                        <tbody>
                            ${sats.map(s => `
                                <tr>
                                    <td><strong style="color:#FFF;">${escapeHtml(s.satellite)}</strong><div class="small-text dim">${escapeHtml(s.operator)}</div></td>
                                    <td class="cyan mono">${escapeHtml(s.sensor_type)}</td>
                                    <td class="hazard mono">${escapeHtml(s.next_acquisition_window)}</td>
                                    <td class="dim">${escapeHtml(s.resolution)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">CALCULATED</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};

/* ============================================================
   22. TAB-FLIGHT COMPANION: EMERGENCY SQUAWK & MILITARY RADAR
   ============================================================ */
window.runSquawkMonitor = async function() {
    const lat = parseFloat(document.getElementById('squawk-lat')?.value || '51.5074');
    const lon = parseFloat(document.getElementById('squawk-lon')?.value || '-0.1278');
    const rad = parseFloat(document.getElementById('squawk-radius')?.value || '300');
    const status = document.getElementById('squawkmonitor-status');
    const results = document.getElementById('squawkmonitor-results');

    if (status) status.innerHTML = `<span class="cyan mono"><span class="engine-pulse-dot"></span> INTERCEPTING SQUAWKS &amp; STRATEGIC AIR...</span>`;

    try {
        const res = await fetch('/api/modules/squawk_monitor', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({lat: lat, lon: lon, radius: rad})
        });
        const d = await res.json();
        if (d.status === 'error') throw new Error(d.error);

        const emerg = d.emergency_squawk_alerts || [];
        const mil = d.military_recon_contacts || [];

        results.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">SECTOR: ${lat.toFixed(2)}, ${lon.toFixed(2)} (${rad} KM)</span>
                        <h2 class="card-title" style="color:#C084FC;">${emerg.length} MAYDAY SQUAWKS // ${mil.length} STRATEGIC MILITARY</h2>
                    </div>
                    <span class="badge ${emerg.length > 0 ? 'hazard' : 'cyan'}">${d.tactical_alert_status}</span>
                </div>
                <div class="card-body">
                    ${emerg.length > 0 ? `
                        <div style="margin-bottom:14px;">
                            <span class="telemetry-label hazard">ACTIVE AIRSPACE EMERGENCY TRANSPONDER CODES</span>
                            <table class="table-tactical" style="width:100%; margin-top:6px;">
                                <thead><tr><th>ICAO</th><th>CALLSIGN</th><th>SQUAWK</th><th>ALERT TYPE</th></tr></thead>
                                <tbody>
                                    ${emerg.map(e => `
                                        <tr>
                                            <td class="cyan mono">${escapeHtml(e.icao24)}</td>
                                            <td style="color:#FFF; font-weight:bold;">${escapeHtml(e.callsign)}</td>
                                            <td class="hazard mono">${e.squawk}</td>
                                            <td><span class="badge hazard">${escapeHtml(e.alert)}</span></td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    ` : ''}

                    <div>
                        <span class="telemetry-label">HIGH-INTEREST MILITARY &amp; STRATEGIC RECONNAISSANCE AIRCRAFT</span>
                        ${mil.length > 0 ? `
                            <table class="table-tactical" style="width:100%; margin-top:6px;">
                                <thead><tr><th>CALLSIGN</th><th>ICAO</th><th>MISSION / AIRFRAME</th><th>ALTITUDE / SPEED</th></tr></thead>
                                <tbody>
                                    ${mil.map(m => `
                                        <tr>
                                            <td class="hazard mono" style="font-weight:bold;">${escapeHtml(m.callsign)}</td>
                                            <td class="cyan mono">${escapeHtml(m.icao24)}</td>
                                            <td style="color:#FFF;">${escapeHtml(m.mission_profile)}</td>
                                            <td class="mono emerald">${m.altitude_feet} ft / ${m.speed_knots} kts</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        ` : `<div class="mono small-text dim" style="padding:8px 0;">No VIP/military callsigns (FORTE, RCH, JAKE, LAGR) detected in current transponder sector.</div>`}
                    </div>
                </div>
            </div>
        `;
        if (status) status.innerHTML = `<span class="emerald">MONITOR ACTIVE</span>`;
    } catch(e) {
        if (status) status.innerHTML = `<span class="critical">ERROR: ${e.message}</span>`;
        if (results) results.innerHTML = `<div class="critical mono" style="padding:16px;">${e.message}</div>`;
    }
};
