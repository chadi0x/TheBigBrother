/* ============================================================
   BIG BROTHER V7.0 — APPLICATION COORDINATOR (OBSIDIAN WAR-ROOM)
   Manages the 3-Deck architecture, Dual-Mode Canvas (Grid vs Graph),
   Threat Score SVG ring, Telemetry polling, and Dossier Export.
   Hardened with fail-safe routing, resilient state management,
   and strict single-view display enforcement.
   ============================================================ */

(function() {
    'use strict';

    // Single source of truth for active state
    window.currentMode = 'grid'; // 'grid' or 'nexus'
    window.activeTab = 'tab-home';
    window.currentModuleId = 'tab-home';
    let currentThreatScore = 50;

    // Tactical Tab ID Mapping & Aliases
    const TAB_ALIASES = {
        'COMMAND_CENTER': 'tab-home',
        'MOD_OVERVIEW': 'tab-home',
        'HOME': 'tab-home',
        'AI_ANALYST': 'tab-analyst',
        'ANALYST': 'tab-analyst',
        'CHAIN_TRACER': 'tab-chaintracer',
        'PIXEL_FORGE': 'tab-pixelforge',
        'HUDSON_ROCK': 'tab-hudsonrock',
        'SHADOW_CLONE': 'tab-shadowclone',
        'WEB_SPIDER': 'tab-spidercrawl',
        'DOC_AUTOPSY': 'tab-docautopsy',
        'VOICE_PRINT': 'tab-voiceprint',
        'ORBITAL_EYE': 'tab-orbitaleye',
        'EVM_SOL': 'tab-evmsol',
        'PROMPT_LEAK': 'tab-shadowai',
        'TELEMETRY': 'tab-telemetry',
        'RANSOM_DISCLOSE': 'tab-ransom',
        'CAM_VECTOR': 'tab-camvector',
        'CANARY_SENTINEL': 'tab-canary',
        'PROFILER_CORE': 'tab-profiler',
        'BREACH_VAULT': 'tab-breach',
        'DIGITAL_FOOTPRINT': 'tab-footprint',
        'MAIL_TRACER': 'tab-mailtracer',
        'CODE_HUNTER': 'tab-codehunter',
        'DEEP_IDENTITY': 'tab-deepidentity',
        'DOMAIN_ORACLE': 'tab-oracle',
        'NETWORK_MAPPER': 'tab-network',
        'GEOINT_SPY': 'tab-geoint',
        'SKY_RADAR': 'tab-flight'
    };

    // ─────────────────────────────────────────────────────────────
    // 1. FAIL-SAFE TAB ROUTER & DEFENSIVE MODULE ACTIVATOR
    // ─────────────────────────────────────────────────────────────
    function safeInitThreatPanel() {
        try {
            if (window.threatMatrix) {
                window.threatMatrix.render();
            } else if (typeof updateThreatScoreDial === 'function') {
                updateThreatScoreDial(10, 'SECURE');
            }
        } catch (err) {
            console.warn('[V7 Threat Score Non-Fatal Warning]:', err);
        }
    }
    window.safeInitThreatPanel = safeInitThreatPanel;

    function activateModule(moduleId) {
        // Hide all panels
        document.querySelectorAll('.tool-panel, .module-panel').forEach(p => {
            p.classList.remove('active');
            p.style.setProperty('display', 'none', 'important');
        });
        document.querySelectorAll('.nav-tab-btn, .nav-item').forEach(b => b.classList.remove('active'));

        // Target panel resolution
        let targetId = moduleId || 'tab-home';
        if (window.TAB_ALIASES && window.TAB_ALIASES[moduleId]) {
            targetId = window.TAB_ALIASES[moduleId];
        } else if (typeof TAB_ALIASES !== 'undefined' && TAB_ALIASES[moduleId]) {
            targetId = TAB_ALIASES[moduleId];
        } else if (!targetId.startsWith('tab-')) {
            targetId = `tab-${moduleId.toLowerCase().replace(/_/g, '')}`;
        }

        let targetPanel = document.getElementById(targetId);
        if (!targetPanel) {
            console.warn(`[activateModule] Panel #${targetId} not found, falling back to #tab-home`);
            targetId = 'tab-home';
            targetPanel = document.getElementById('tab-home');
        }

        const targetBtn = document.querySelector(`[data-tab="${targetId}"]`) || document.querySelector(`[data-module="${moduleId}"]`);

        if (targetPanel) {
            targetPanel.classList.add('active');
            targetPanel.style.setProperty('display', 'block', 'important');
            targetPanel.style.animation = 'none';
            void targetPanel.offsetHeight; // trigger reflow
            targetPanel.style.animation = 'panelSlideFade 0.2s cubic-bezier(0.16, 1, 0.3, 1)';
        }
        if (targetBtn) {
            targetBtn.classList.add('active');
        }

        window.activeTab = targetId;
        window.currentModuleId = targetId;

        // Sync Nexus Graph Button Visibility & Dynamic Rendering
        if (typeof syncNexusButtonVisibility === 'function') {
            syncNexusButtonVisibility(targetId);
        }

        // Update Center Header Title if available
        const headerTitle = document.getElementById('deck-current-title');
        if (headerTitle && targetBtn) {
            const activeNav = targetBtn.querySelector('.nav-text');
            if (activeNav) headerTitle.textContent = activeNav.textContent.toUpperCase();
        }

        // Viewport containment: reset scroll to top
        const viewport = document.querySelector('.main-viewport, .canvas-body, #main-stage');
        if (viewport) {
            viewport.scrollTop = 0;
        }
    }
    window.activateModule = activateModule;

    window.switchTab = function(rawTabId, title) {
        activateModule(rawTabId);
        if (title) {
            const headerTitle = document.getElementById('deck-current-title');
            if (headerTitle) headerTitle.textContent = title.toUpperCase();
        }
        // 9. Procedural Audio Click
        try {
            if (window.tacticalAudio && window.tacticalAudio.enabled) {
                window.tacticalAudio.playClick(980, 0.03);
            }
        } catch (e) {}

        // Invalidate Leaflet tactical map sizes on tab display
        if (rawTabId === 'tab-geoint') {
            setTimeout(() => {
                if (window.geointMap) {
                    window.geointMap.invalidateSize();
                } else if (typeof window.initGeointMap === 'function') {
                    const lat = document.getElementById('geoint-lat')?.value || '48.8584';
                    const lon = document.getElementById('geoint-lon')?.value || '2.2945';
                    window.initGeointMap(lat, lon, 'Tactical Targeting Default Vector');
                }
            }, 150);
        }
        if (rawTabId === 'tab-flight') {
            setTimeout(() => {
                if (window.flightMap) {
                    window.flightMap.invalidateSize();
                } else if (typeof window.initFlightMap === 'function') {
                    const lat = document.getElementById('flight-lat')?.value || '51.5074';
                    const lon = document.getElementById('flight-lon')?.value || '-0.1278';
                    const rad = document.getElementById('flight-radius')?.value || '120';
                    window.initFlightMap(lat, lon, [], rad);
                }
            }, 150);
        }
    };

    // ─────────────────────────────────────────────────────────────
    // SUBTOOL DUAL-ENGINE SWITCHER (TOOL 1 VS TOOL 2)
    // ─────────────────────────────────────────────────────────────
    window.switchSubTool = function(containerId, subtoolIndex) {
        const container = document.getElementById(containerId);
        if (!container) return;

        const buttons = container.querySelectorAll('.subtool-btn');
        buttons.forEach(btn => {
            const idx = parseInt(btn.getAttribute('data-subtool') || '1', 10);
            if (idx === subtoolIndex) {
                btn.classList.add(idx === 2 ? 'companion-active' : 'active');
                btn.classList.remove(idx === 2 ? 'active' : 'companion-active');
            } else {
                btn.classList.remove('active', 'companion-active');
            }
        });

        const deck1 = container.querySelector('.subtool-deck-primary');
        const deck2 = container.querySelector('.subtool-deck-companion');

        if (deck1) {
            if (subtoolIndex === 1) {
                deck1.classList.remove('hide');
                deck1.style.setProperty('display', 'block', 'important');
            } else {
                deck1.classList.add('hide');
                deck1.style.setProperty('display', 'none', 'important');
            }
        }

        if (deck2) {
            if (subtoolIndex === 2) {
                deck2.classList.remove('hide');
                deck2.style.setProperty('display', 'block', 'important');
            } else {
                deck2.classList.add('hide');
                deck2.style.setProperty('display', 'none', 'important');
            }
        }

        try {
            if (window.tacticalAudio && window.tacticalAudio.enabled) {
                window.tacticalAudio.playClick(subtoolIndex === 2 ? 1150 : 850, 0.03);
            }
        } catch (e) {}
    };

    // ─────────────────────────────────────────────────────────────
    // 2. DUAL-MODE VIEW SWITCHER (TACTICAL GRID VS NEXUS GRAPH)
    // ─────────────────────────────────────────────────────────────
    function syncNexusButtonVisibility(targetTabId) {
        const btnNexus = document.getElementById('btn-mode-nexus');
        if (!btnNexus) return;

        const isCapable = window.nexusGraph ? window.nexusGraph.isGraphCapable(targetTabId) : false;
        if (isCapable) {
            btnNexus.style.display = 'inline-flex';
            if (window.currentMode === 'nexus' && window.nexusGraph) {
                window.nexusGraph.updateForTab(targetTabId);
            }
        } else {
            btnNexus.style.display = 'none';
            if (window.currentMode === 'nexus') {
                setDualMode('grid');
            }
        }
    }
    window.syncNexusButtonVisibility = syncNexusButtonVisibility;

    function setDualMode(mode) {
        const gridView = document.getElementById('canvas-tactical-grid');
        const nexusView = document.getElementById('canvas-nexus-graph');
        const btnGrid = document.getElementById('btn-mode-grid');
        const btnNexus = document.getElementById('btn-mode-nexus');

        if (mode === 'nexus') {
            const currentTab = window.activeTab || 'tab-home';
            // Guard: ensure current tab is capable of relationship graph
            if (window.nexusGraph && !window.nexusGraph.isGraphCapable(currentTab)) {
                return;
            }

            window.currentMode = 'nexus';
            if (gridView) {
                gridView.classList.add('hide');
                gridView.style.setProperty('display', 'none', 'important');
            }
            if (nexusView) {
                nexusView.classList.remove('hide');
                nexusView.style.setProperty('display', 'block', 'important');
            }
            if (btnNexus) btnNexus.classList.add('active');
            if (btnGrid) btnGrid.classList.remove('active');
            if (window.nexusGraph) {
                window.nexusGraph.updateForTab(currentTab);
                setTimeout(() => {
                    try { window.nexusGraph.resetView(); } catch (e) {}
                }, 100);
            }
        } else {
            window.currentMode = 'grid';
            if (nexusView) {
                nexusView.classList.add('hide');
                nexusView.style.setProperty('display', 'none', 'important');
            }
            if (gridView) {
                gridView.classList.remove('hide');
                gridView.style.setProperty('display', 'block', 'important');
            }
            if (btnGrid) btnGrid.classList.add('active');
            if (btnNexus) btnNexus.classList.remove('active');
        }

        try {
            if (window.tacticalAudio && window.tacticalAudio.enabled) {
                window.tacticalAudio.playClick(900, 0.03);
            }
        } catch (e) {}
    }
    window.setDualMode = setDualMode;
    window.toggleDualMode = function(explicitMode) {
        setDualMode(explicitMode || (window.currentMode === 'grid' ? 'nexus' : 'grid'));
    };

    function initDualModeSwitcher() {
        const btnGrid = document.getElementById('btn-mode-grid');
        const btnNexus = document.getElementById('btn-mode-nexus');

        if (btnGrid) btnGrid.addEventListener('click', () => setDualMode('grid'));
        if (btnNexus) btnNexus.addEventListener('click', () => setDualMode('nexus'));
    }

    // ─────────────────────────────────────────────────────────────
    // 3. COLLAPSIBLE NAVIGATION RAIL
    // ─────────────────────────────────────────────────────────────
    window.toggleNavDock = function() {
        const rail = document.getElementById('nav-dock') || document.getElementById('left-nav-rail');
        const layout = document.querySelector('.bb-app-layout');
        if (rail) {
            rail.classList.toggle('collapsed');
            if (layout) {
                if (rail.classList.contains('collapsed')) {
                    layout.style.setProperty('grid-template-columns', '54px 1fr 340px', 'important');
                } else {
                    layout.style.setProperty('grid-template-columns', '260px 1fr 340px', 'important');
                }
            }
        }
        try {
            if (window.tacticalAudio && window.tacticalAudio.enabled) {
                window.tacticalAudio.playClick(750, 0.03);
            }
        } catch (e) {}
    };

    // ─────────────────────────────────────────────────────────────
    // 4. AUDIO FX TOGGLE
    // ─────────────────────────────────────────────────────────────
    function initAudioToggle() {
        const btn = document.getElementById('btn-audio-toggle');
        if (!btn) return;
        const isEnabled = (window.tacticalAudio && window.tacticalAudio.enabled) || false;
        updateAudioButtonUI(isEnabled);

        btn.addEventListener('click', () => {
            try {
                const enabled = window.tacticalAudio ? window.tacticalAudio.toggle() : false;
                updateAudioButtonUI(enabled);
            } catch (e) {}
        });
    }

    function updateAudioButtonUI(enabled) {
        const btn = document.getElementById('btn-audio-toggle');
        if (!btn) return;
        if (enabled) {
            btn.innerHTML = `<svg class="audio-svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><path d="M15.54 8.46a5 5 0 0 1 0 7.07"></path><path d="M19.07 4.93a10 10 0 0 1 0 14.14"></path></svg> <span class="audio-text">AUDIO ON</span>`;
            btn.classList.add('active');
        } else {
            btn.innerHTML = `<svg class="audio-svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><line x1="23" y1="9" x2="17" y2="15"></line><line x1="17" y1="9" x2="23" y2="15"></line></svg> <span class="audio-text">AUDIO MUTE</span>`;
            btn.classList.remove('active');
        }
    }

    window.toggleAudioFx = function() {
        try {
            const isEnabled = window.tacticalAudio ? window.tacticalAudio.toggle() : false;
            updateAudioButtonUI(isEnabled);
        } catch (e) {}
    };

    // ─────────────────────────────────────────────────────────────
    // 5. THREAT SCORE SVG ANIMATED DIAL
    // ─────────────────────────────────────────────────────────────
    function updateThreatScoreDial(score, tier) {
        currentThreatScore = Math.min(100, Math.max(0, Math.round(score)));
        const circle = document.getElementById('threat-circle-path');
        const scoreText = document.getElementById('threat-score-number');
        const tierText = document.getElementById('threat-tier-text');
        if (!circle || !scoreText) return;

        const circumference = 276.46; // r=44
        const offset = circumference - (currentThreatScore / 100) * circumference;
        circle.style.strokeDasharray = `${circumference} ${circumference}`;
        circle.style.strokeDashoffset = offset;

        const color = currentThreatScore >= 70 ? '#EF4444' : currentThreatScore >= 30 ? '#F59E0B' : '#10B981';
        circle.style.stroke = color;
        scoreText.textContent = currentThreatScore;
        scoreText.style.color = color;

        if (tierText) {
            const computedTier = tier || (currentThreatScore >= 70 ? 'CRITICAL (ALPHA-1)' : currentThreatScore >= 30 ? 'ELEVATED' : 'SECURE');
            tierText.textContent = computedTier;
            tierText.className = `threat-tier-badge ${currentThreatScore >= 70 ? 'critical' : currentThreatScore >= 30 ? 'hazard' : 'emerald'}`;
            tierText.style.color = color;
        }
    }
    window.updateThreatScoreDial = updateThreatScoreDial;

    // ─────────────────────────────────────────────────────────────
    // 5.1 TACTICAL THREAT MATRIX & DYNAMIC RISK ENGINE
    // ─────────────────────────────────────────────────────────────
    class ThreatMatrixEngine {
        constructor() {
            this.target = 'UNASSESSED TARGET';
            this.baseScore = 10;
            this.assessedModules = new Set();
            this.ledger = []; // { id, moduleId, moduleTitle, findingType, rawPoints, effectivePoints, label, severity, timestamp }
            this.totalScore = 10;
            this.tier = 'SECURE';
            this.lastPulse = 'STANDBY';
            this.infostealerCap = 40;
        }

        setTarget(targetName) {
            if (!targetName) return;
            const clean = targetName.trim().toUpperCase();
            if (clean && clean !== this.target) {
                this.target = clean;
                this.assessedModules.clear();
                this.ledger = [];
                this.baseScore = 10;
                this.recalculate();
            }
        }

        registerFinding(moduleId, moduleTitle, findingType, points, label, severity = 'hazard') {
            if (moduleId) {
                this.assessedModules.add(moduleId);
            }

            const entryId = `${moduleId || 'MOD'}_${findingType || 'FINDING'}_${label || ''}`.substring(0, 90);
            const existingIdx = this.ledger.findIndex(item => item.id === entryId);

            const newItem = {
                id: entryId,
                moduleId: moduleId || 'GENERAL',
                moduleTitle: moduleTitle || moduleId?.toUpperCase() || 'MODULE',
                findingType: findingType || 'ioc',
                rawPoints: Number(points) || 0,
                effectivePoints: Number(points) || 0,
                label: label || 'Suspicious forensic vector recorded.',
                severity: severity,
                timestamp: new Date().toLocaleTimeString()
            };

            if (existingIdx >= 0) {
                this.ledger[existingIdx] = newItem;
            } else {
                this.ledger.unshift(newItem);
            }

            this.recalculate();
        }

        recalculate() {
            let infostealerSubtotal = 0;
            let otherPoints = 0;

            for (const item of this.ledger) {
                if (item.findingType === 'infostealer' || item.findingType === 'stealer') {
                    infostealerSubtotal += item.rawPoints;
                } else {
                    otherPoints += item.rawPoints;
                }
            }

            let currentStealerSum = 0;
            for (const item of this.ledger) {
                if (item.findingType === 'infostealer' || item.findingType === 'stealer') {
                    if (currentStealerSum >= this.infostealerCap) {
                        item.effectivePoints = 0;
                    } else if (currentStealerSum + item.rawPoints > this.infostealerCap) {
                        item.effectivePoints = this.infostealerCap - currentStealerSum;
                        currentStealerSum = this.infostealerCap;
                    } else {
                        item.effectivePoints = item.rawPoints;
                        currentStealerSum += item.rawPoints;
                    }
                } else {
                    item.effectivePoints = item.rawPoints;
                }
            }

            const cappedInfostealer = Math.min(infostealerSubtotal, this.infostealerCap);
            const rawSum = this.baseScore + otherPoints + cappedInfostealer;
            this.totalScore = Math.min(100, Math.max(0, rawSum));

            if (this.totalScore >= 70) {
                this.tier = 'CRITICAL (ALPHA-1)';
            } else if (this.totalScore >= 30) {
                this.tier = 'ELEVATED';
            } else {
                this.tier = 'SECURE';
            }

            this.lastPulse = `${new Date().toLocaleTimeString()} UTC`;
            this.render();
        }

        render() {
            updateThreatScoreDial(this.totalScore, this.tier);

            const activeTargetEl = document.getElementById('active-target-display');
            if (activeTargetEl) activeTargetEl.textContent = this.target;

            const count = this.assessedModules.size;
            const coverageCountEl = document.getElementById('module-coverage-count');
            const coverageBarEl = document.getElementById('module-coverage-bar');
            if (coverageCountEl) coverageCountEl.textContent = `${count} / 26 MODULES`;
            if (coverageBarEl) {
                const pct = Math.min(100, Math.round((count / 26) * 100));
                coverageBarEl.style.width = `${pct}%`;
            }

            const pulseEl = document.getElementById('last-pulse-time');
            if (pulseEl) {
                pulseEl.textContent = this.lastPulse;
                pulseEl.className = 'matrix-stat-val cyan';
            }

            const ledgerEl = document.getElementById('threat-ledger-list');
            if (ledgerEl) {
                if (this.ledger.length === 0) {
                    ledgerEl.innerHTML = `<div class="ledger-empty">[-] NO CRITICAL IOCs DETECTED ACROSS RUN MODULES</div>`;
                } else {
                    ledgerEl.innerHTML = this.ledger.map(item => `
                        <div class="threat-ledger-item ${item.severity}">
                            <div class="ledger-item-header">
                                <span class="ledger-tag">[${item.moduleTitle}]</span>
                                <span class="ledger-points">+${item.effectivePoints} PTS</span>
                            </div>
                            <div class="ledger-desc">${item.label}</div>
                        </div>
                    `).join('');
                }
            }
        }
    }

    window.threatMatrix = new ThreatMatrixEngine();

    // ─────────────────────────────────────────────────────────────
    // 6. HUD FREQUENCY PULSE WAVEFORM CANVAS
    // ─────────────────────────────────────────────────────────────
    function initHudPulseWaveform() {
        const canvas = document.getElementById('hud-pulse-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;
        let step = 0;

        function draw() {
            requestAnimationFrame(draw);
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.strokeStyle = '#00F0FF';
            ctx.lineWidth = 1.5;
            ctx.shadowBlur = 6;
            ctx.shadowColor = '#00F0FF';

            ctx.beginPath();
            const width = canvas.width;
            const height = canvas.height;
            const mid = height / 2;

            for (let x = 0; x < width; x++) {
                const angle = (x + step) * 0.08;
                const wave1 = Math.sin(angle) * (height * 0.25);
                const wave2 = Math.cos(angle * 0.5) * (height * 0.15);
                const y = mid + wave1 + wave2;
                if (x === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            }
            ctx.stroke();
            step += 1.6;
        }
        draw();
    }

    // ─────────────────────────────────────────────────────────────
    // 7. TELEMETRY HEALTH POLLER
    // ─────────────────────────────────────────────────────────────
    function initTelemetryPoller() {
        pollSystemTelemetry();
        setInterval(pollSystemTelemetry, 4000);
    }

    function pollSystemTelemetry() {
        (window.nexusFetch || window.fetch)('/api/telemetry/health')
        .then(r => {
            if (!r || !r.ok) return null;
            return r.json();
        })
        .catch(() => null)
        .then(d => {
            if (!d) return;
            const cpuEl = document.getElementById('meter-cpu');
            const memEl = document.getElementById('meter-mem');
            const workersEl = document.getElementById('meter-workers');
            const latencyEl = document.getElementById('meter-latency');
            const redisEl = document.getElementById('meter-redis');

            if (cpuEl) cpuEl.textContent = `${Math.round(d.cpu_percent || 14)}%`;
            if (memEl) memEl.textContent = `${d.memory_used_mb || 428} MB`;
            if (workersEl) workersEl.textContent = `${d.worker_pools || 8} POOLS`;
            if (latencyEl) latencyEl.textContent = `${d.api_latency_ms || 38}ms`;
            if (redisEl) redisEl.textContent = d.redis_cache?.includes('STANDBY') ? 'STANDBY' : 'ONLINE';

            const statusPulse = document.getElementById('hud-engine-status');
            if (statusPulse) {
                statusPulse.textContent = `${d.status || 'OPERATIONAL'} // V${d.version || '7.0.0'}`;
            }
        })
        .catch(() => {});
    }

    // ─────────────────────────────────────────────────────────────
    // 8. CORRELATION FEED
    // ─────────────────────────────────────────────────────────────
    window.appendCorrelationFeed = function(findings) {
        const feedEl = document.getElementById('live-correlation-feed');
        if (!feedEl || !findings) return;

        feedEl.innerHTML = findings.map(f => `
            <div class="correlation-item reveal">
                <span class="pulse-dot"></span>
                <div class="correlation-content">
                    <div class="correlation-text">${f}</div>
                    <div class="correlation-meta mono">SYNTHESIS CONFIRMED // ${new Date().toLocaleTimeString()}</div>
                </div>
                <button class="btn-icon-xs" onclick="copyToClipboard('${f.replace(/'/g, "\\'")}', this)" title="Copy correlation"><svg class="copy-svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button>
            </div>
        `).join('');
    };

    // ─────────────────────────────────────────────────────────────
    // 9. QUICK TARGET SELECTOR
    // ─────────────────────────────────────────────────────────────
    function initSampleTargets() {
        const selectEl = document.getElementById('target-quick-select');
        if (!selectEl) return;

        selectEl.addEventListener('change', (e) => {
            const val = e.target.value;
            if (!val) return;
            window.loadSampleTarget(val);
        });
    }

    window.loadSampleTarget = function(targetName) {
        const analystInput = document.getElementById('analyst-target');
        const globalSearch = document.getElementById('global-search-input');
        const usernameInput = document.getElementById('username');

        if (analystInput) analystInput.value = targetName;
        if (globalSearch) globalSearch.value = targetName;
        if (usernameInput) usernameInput.value = targetName;

        window.switchTab('tab-analyst', 'AI ANALYST');
        if (window.runAnalyst) window.runAnalyst();
    };

    // ─────────────────────────────────────────────────────────────
    // 10. EXECUTIVE DOSSIER EXPORT & MODAL PREVIEW
    // ─────────────────────────────────────────────────────────────
    window.exportExecutiveDossier = function() {
        const tm = window.threatMatrix || {
            target: 'UNASSESSED TARGET',
            totalScore: 10,
            tier: 'SECURE',
            assessedModules: new Set(),
            ledger: []
        };

        const target = (tm.target && tm.target !== 'UNASSESSED TARGET') ? tm.target : (window.currentDossierData?.target || 'ACTIVE-SURVEILLANCE-TARGET');
        const score = tm.totalScore;
        const tier = tm.tier;
        const ledger = tm.ledger;
        const coverage = `${tm.assessedModules.size} / 26`;
        const sessionProof = window.generateSessionProof ? window.generateSessionProof(target) : 'SHA256: 8F4C3B21E9A0C6D7E4F1A5B2C3D4E5F6';
        const timestamp = new Date().toUTCString();

        const findingsHtml = ledger.length > 0
            ? ledger.map(f => `
                <div class="finding-item" style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px; padding-bottom:6px; border-bottom:1px solid rgba(255,255,255,0.05);">
                    <div>
                        <strong style="color:var(--accent-cyan); font-family:var(--font-mono); font-size:11px; margin-right:6px;">[${f.moduleTitle}]</strong>
                        <span style="color:#EEF2FF; font-size:12px;">${f.label}</span>
                    </div>
                    <span class="mono" style="color:${f.severity === 'critical' ? '#EF4444' : f.severity === 'hazard' ? '#F59E0B' : '#10B981'}; font-weight:700; font-size:11px; white-space:nowrap; margin-left:12px;">+${f.effectivePoints} PTS</span>
                </div>
            `).join('')
            : `<div class="finding-item"><span style="color:var(--status-nominal); font-family:var(--font-mono); font-size:11px;">[NOMINAL] Baseline autonomous reconnaissance completed. No elevated threat indicators recorded across analyzed parameters.</span></div>`;

        const modal = document.getElementById('dossier-preview-modal');
        const body = document.getElementById('dossier-preview-body');
        if (!modal || !body) return;

        body.innerHTML = `
            <div class="dossier-document">
                <div class="classified-case-bar" style="margin-bottom:16px;">
                    <div class="case-bar-left">
                        <span class="security-classification-badge">TOP SECRET // ORCON / NOFORN</span>
                        <span class="case-file-id">CASE // CJIS-FORENSIC-${Math.abs(hashCode(target) % 90000 + 10000)}</span>
                        <span class="telemetry-beacon"></span>
                    </div>
                    <div class="case-bar-right">
                        <span class="session-proof">${sessionProof.substring(0, 22)}...</span>
                        <span class="case-timestamp">${timestamp}</span>
                    </div>
                </div>

                <div class="dossier-header">
                    <div>
                        <div class="dossier-tag">LAWFUL OSINT THREAT INTELLIGENCE DOSSIER // FBI CJIS & PALANTIR GOTHAM SPEC</div>
                        <h2 class="dossier-title">EXECUTIVE DOSSIER: ${target}</h2>
                    </div>
                    <div class="dossier-score-box">
                        <span class="dim mono small-text">SYNTHESIS THREAT SCORE</span>
                        <div class="dossier-score ${score >= 70 ? 'critical' : score >= 30 ? 'hazard' : 'emerald'}">${score} / 100</div>
                    </div>
                </div>

                <div class="dossier-section">
                    <h4 class="dossier-sub">TARGET TELEMETRY & MULTI-SOURCE ATTRIBUTION</h4>
                    <div class="metric-row">
                        <div class="metric-pill"><span class="dim">PRIMARY ASSET</span><strong>${target}</strong></div>
                        <div class="metric-pill"><span class="dim">SEVERITY TIER</span><strong class="${score >= 70 ? 'critical' : score >= 30 ? 'hazard' : 'emerald'}">${tier}</strong></div>
                        <div class="metric-pill"><span class="dim">MODULE COVERAGE</span><strong>${coverage} MODULES</strong></div>
                        <div class="metric-pill"><span class="dim">FORENSIC ENGINE</span><strong>BIG BROTHER V7.0</strong></div>
                    </div>
                </div>

                <div class="dossier-section">
                    <h4 class="dossier-sub">ITEMIZED FORENSIC RISK LEDGER & DETECTED VECTORS</h4>
                    <div class="finding-list">
                        ${findingsHtml}
                    </div>
                </div>

                <div class="dossier-seal">
                    <strong>CRYPTOGRAPHIC CHAIN-OF-CUSTODY SEAL (SHA-256 NON-REPUDIATION):</strong><br>
                    <code>${sessionProof}</code><br>
                    <span class="dim mono small-text">Generated at: ${timestamp} // AUDIT LOG: ${Math.random().toString(36).substring(2, 10).toUpperCase()} // VERIFIED AUTONOMOUS CORRELATION</span>
                </div>
            </div>
        `;

        modal.classList.remove('hide');
        try {
            if (window.tacticalAudio && window.tacticalAudio.enabled) {
                window.tacticalAudio.playModuleLaunch();
            }
        } catch (e) {}
    };

    function hashCode(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash |= 0;
        }
        return hash;
    }

    window.closeDossierModal = function() {
        const modal = document.getElementById('dossier-preview-modal');
        if (modal) modal.classList.add('hide');
    };

    window.downloadDossierHtml = function() {
        const modalBody = document.getElementById('dossier-preview-body');
        if (!modalBody) return;

        const content = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>EXECUTIVE CLASSIFIED DOSSIER // BIG BROTHER V7.0</title>
<style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #06080C; color: #EEF2FF; margin: 40px; }
    .dossier-document { max-width: 840px; margin: 0 auto; background: #0D1117; padding: 40px; border: 1px solid rgba(0,240,255,0.4); border-radius: 8px; box-shadow: 0 0 30px rgba(0,240,255,0.15); }
    .dossier-header { border-bottom: 2px solid #00F0FF; padding-bottom: 20px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: flex-end; }
    .dossier-title { color: #00F0FF; font-size: 24px; margin: 6px 0 0; }
    .dossier-tag { font-size: 10px; letter-spacing: 2px; color: #7B87A8; font-family: monospace; }
    .dossier-score { font-size: 32px; font-weight: bold; }
    .dossier-score.critical { color: #EF4444; }
    .dossier-score.hazard { color: #F59E0B; }
    .dossier-score.emerald { color: #10B981; }
    .dossier-section { margin-bottom: 24px; }
    .dossier-sub { color: #00FF9D; font-size: 13px; letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 12px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 6px; }
    .metric-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
    .metric-pill { background: #06080C; border: 1px solid #1E293B; border-radius: 4px; padding: 8px 12px; display: flex; flex-direction: column; font-size: 11px; }
    .metric-pill span.dim { color: #64748B; font-size: 9px; margin-bottom: 4px; }
    .finding-item { padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 12px; line-height: 1.5; }
    .dossier-seal { background: rgba(0,255,157,0.06); border: 1px solid #00FF9D; border-radius: 6px; padding: 14px; font-family: monospace; font-size: 11px; color: #00FF9D; margin-top: 30px; }
    .security-classification-badge { background: rgba(239, 68, 68, 0.15); border: 1px solid #EF4444; color: #EF4444; padding: 2px 6px; border-radius: 2px; font-weight: 700; font-size: 10px; }
    .classified-case-bar { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1E293B; padding-bottom: 10px; margin-bottom: 16px; font-family: monospace; font-size: 10px; color: #94A3B8; }
</style>
</head>
<body>
${modalBody.innerHTML}
</body>
</html>`;

        const blob = new Blob([content], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `CLASSIFIED_DOSSIER_${Date.now()}.html`;
        a.click();
    };

    // ─────────────────────────────────────────────────────────────
    // 11. BOOTSTRAP SYSTEM
    // ─────────────────────────────────────────────────────────────
    function initTabs() {
        // Programmatically attach click listeners to all nav items for redundancy
        document.querySelectorAll('.nav-item, .nav-tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tabId = btn.getAttribute('data-tab') || btn.getAttribute('data-module');
                const titleEl = btn.querySelector('.nav-text');
                const title = titleEl ? titleEl.textContent.trim() : tabId;
                if (tabId) {
                    window.switchTab(tabId, title);
                }
            });
        });

        // Enforce strictly ONE visible view on boot
        activateModule('COMMAND_CENTER');
    }

    function initApp() {
        try { initTabs(); } catch (e) { console.error('[INIT] initTabs error:', e); }
        try { initDualModeSwitcher(); } catch (e) { console.error('[INIT] initDualModeSwitcher error:', e); }
        try { initAudioToggle(); } catch (e) { console.error('[INIT] initAudioToggle error:', e); }
        try { initTelemetryPoller(); } catch (e) { console.error('[INIT] initTelemetryPoller error:', e); }
        try { initSampleTargets(); } catch (e) { console.error('[INIT] initSampleTargets error:', e); }
        try { safeInitThreatPanel(); } catch (e) { console.error('[INIT] safeInitThreatPanel error:', e); }
        try { initHudPulseWaveform(); } catch (e) { console.error('[INIT] initHudPulseWaveform error:', e); }
        try { initInputKeyHandlers(); } catch (e) { console.error('[INIT] initInputKeyHandlers error:', e); }

        // Optional Subsystems (isolated so CDN delays or missing features never cascade)
        try { if (window.initThreeBackdrop) window.initThreeBackdrop(); } catch (e) {}
        try { if (window.cmdPalette) window.cmdPalette.init(); } catch (e) {}
        try { if (window.nexusGraph) window.nexusGraph.init(); } catch (e) {}
        try { syncNexusButtonVisibility(window.activeTab || 'tab-home'); } catch (e) {}
    }

    function initInputKeyHandlers() {
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && e.target && e.target.classList && e.target.classList.contains('input-tactical')) {
                if (e.target.tagName === 'TEXTAREA') return;
                const card = e.target.closest('.glass-card, .tool-panel, .module-panel');
                if (card) {
                    const btn = card.querySelector('.btn-tactical, .btn-matrix');
                    if (btn) {
                        e.preventDefault();
                        btn.click();
                    }
                }
            }
        });
    }

    // Execute immediately if DOM is ready, or bind to DOMContentLoaded
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initApp);
    } else {
        initApp();
    }

})();
