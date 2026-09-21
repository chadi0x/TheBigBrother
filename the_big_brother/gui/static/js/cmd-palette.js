/* ============================================================
   BIG BROTHER V7.0 — COMMAND PALETTE (CMD+K)
   Tactical search & launcher across all 36 modules, actions,
   and investigation dossiers with full keyboard navigation.
   ============================================================ */

class CommandPalette {
    constructor() {
        this.isOpen = false;
        this.selectedIndex = 0;
        this.items = [];
        this.filteredItems = [];
    }

    init() {
        this._buildIndex();
        this._bindEvents();
    }

    _buildIndex() {
        this.items = [
            // Core Synthesis
            { id: 'tab-home', title: 'Command Center // HUD Overview', category: 'SYNTHESIS & COMMAND', shortcut: 'G H', tag: 'COMMAND' },
            { id: 'tab-analyst', title: 'AI Analyst // Multi-Agent Correlation', category: 'SYNTHESIS & COMMAND', shortcut: 'G A', tag: 'ANALYST' },

            // Advanced Labs
            { id: 'tab-chaintracer', title: 'Chain Tracer // Cross-Chain Heuristics', category: 'ADVANCED LABS', shortcut: 'L C', tag: 'CHAIN' },
            { id: 'tab-pixelforge', title: 'Pixel Forge // ELA & Image Tampering', category: 'ADVANCED LABS', shortcut: 'L P', tag: 'PIXEL' },
            { id: 'tab-hudsonrock', title: 'Hudson Rock // Infostealer Cavalier', category: 'ADVANCED LABS', shortcut: 'L H', tag: 'HUDSON' },
            { id: 'tab-shadowclone', title: 'Shadow Clone // Persona De-anonymizer', category: 'ADVANCED LABS', shortcut: 'L S', tag: 'CLONE' },
            { id: 'tab-spidercrawl', title: 'Spider Crawl // Deep Entity Crawler', category: 'ADVANCED LABS', shortcut: 'L W', tag: 'SPIDER' },
            { id: 'tab-docautopsy', title: 'Doc Autopsy // Metadata & Canary Forensics', category: 'ADVANCED LABS', shortcut: 'L D', tag: 'AUTOPSY' },
            { id: 'tab-voiceprint', title: 'Voice Print // Synthetic Audio Biometrics', category: 'ADVANCED LABS', shortcut: 'L V', tag: 'VOICE' },

            // Deep Intel
            { id: 'tab-orbitaleye', title: 'Orbital Eye // Satellite Recon & Sun Azimuth', category: 'DEEP RECON', shortcut: 'I O', tag: 'ORBITAL' },
            { id: 'tab-evmsol', title: 'EVM Tracer // Drainer Detection', category: 'DEEP RECON', shortcut: 'I E', tag: 'EVM' },
            { id: 'tab-shadowai', title: 'Prompt Leak // LLM & Prompt Disclosure Audit', category: 'DEEP RECON', shortcut: 'I A', tag: 'PROMPT' },
            { id: 'tab-telemetry', title: 'Telemetry Hunter // AdTech Marketing Beacons', category: 'DEEP RECON', shortcut: 'I T', tag: 'TELEMETRY' },
            { id: 'tab-ransom', title: 'Ransom Disclose // Extortion Gang Shame Blogs', category: 'DEEP RECON', shortcut: 'I R', tag: 'RANSOM' },
            { id: 'tab-camvector', title: 'Cam Vector // RTSP & IoT Stream Feeds', category: 'DEEP RECON', shortcut: 'I C', tag: 'CAM' },
            { id: 'tab-canary', title: 'Canary Sentinel // Deception Tracking Beacons', category: 'DEEP RECON', shortcut: 'I K', tag: 'CANARY' },

            // Profiling & Identity
            { id: 'tab-profiler', title: 'Target Profiler // Multi-Platform OSINT', category: 'IDENTITY & ACCESS', shortcut: 'P P', tag: 'PROFILER' },
            { id: 'tab-breach', title: 'Breach Vault // Leaked Credential Aggregator', category: 'IDENTITY & ACCESS', shortcut: 'P B', tag: 'BREACH' },
            { id: 'tab-footprint', title: 'Digital Footprint // Holehe Social Mapping', category: 'IDENTITY & ACCESS', shortcut: 'P F', tag: 'FOOTPRINT' },
            { id: 'tab-mailtracer', title: 'Mail Tracer // MX & Infiltration Probe', category: 'IDENTITY & ACCESS', shortcut: 'P M', tag: 'MAIL' },
            { id: 'tab-codehunter', title: 'Code Hunter // GitHub Leaked Secrets', category: 'IDENTITY & ACCESS', shortcut: 'P C', tag: 'CODE' },
            { id: 'tab-deepidentity', title: 'Deep Identity // StyleGAN Avatar Detector', category: 'IDENTITY & ACCESS', shortcut: 'P D', tag: 'IDENTITY' },

            // Infra & Geo
            { id: 'tab-oracle', title: 'Domain Oracle // Subdomain & WHOIS Deep Scan', category: 'INFRASTRUCTURE & GEO', shortcut: 'G D', tag: 'ORACLE' },
            { id: 'tab-network', title: 'Network Mapper // Port & Topology Scan', category: 'INFRASTRUCTURE & GEO', shortcut: 'G N', tag: 'NETWORK' },
            { id: 'tab-geoint', title: 'GEOINT Spy // Coordinate Sun & Location Intel', category: 'INFRASTRUCTURE & GEO', shortcut: 'G G', tag: 'GEOINT' },
            { id: 'tab-flight', title: 'Sky Radar // Live Aircraft ADS-B Telemetry', category: 'INFRASTRUCTURE & GEO', shortcut: 'G S', tag: 'SKY' },

            // Global Actions
            { id: 'action-export', title: 'Export Executive Dossier (Cryptographic Seal)', category: 'GLOBAL ACTIONS', action: () => window.exportExecutiveDossier(), tag: 'EXPORT' },
            { id: 'action-toggle-view', title: 'Toggle View: Tactical Grid / Nexus Graph', category: 'GLOBAL ACTIONS', action: () => window.toggleDualMode(), tag: 'VIEW' },
            { id: 'action-toggle-audio', title: 'Toggle Tactical Audio FX', category: 'GLOBAL ACTIONS', action: () => window.toggleAudioFx(), tag: 'AUDIO' },
            { id: 'action-sample-apt', title: 'Load Target: APT-41 State Actor Case', category: 'SAMPLE TARGETS', action: () => window.loadSampleTarget('APT-41 Operative'), tag: 'TARGET' },
            { id: 'action-sample-drainer', title: 'Load Target: Inferno Drainer Nexus', category: 'SAMPLE TARGETS', action: () => window.loadSampleTarget('Inferno Drainer Sybil'), tag: 'TARGET' }
        ];
        this.filteredItems = [...this.items];
    }

    _bindEvents() {
        window.addEventListener('keydown', (e) => {
            if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                this.toggle();
            } else if (e.key === 'Escape' && this.isOpen) {
                this.close();
            }
        });
    }

    open() {
        const modal = document.getElementById('cmd-palette-modal');
        const input = document.getElementById('cmd-palette-input');
        if (!modal || !input) return;

        this.isOpen = true;
        this.selectedIndex = 0;
        input.value = '';
        this.filter('');
        modal.classList.remove('hide');
        setTimeout(() => input.focus(), 50);

        if (window.tacticalAudio) {
            window.tacticalAudio.playClick(950, 0.03);
        }
    }

    close() {
        const modal = document.getElementById('cmd-palette-modal');
        if (modal) modal.classList.add('hide');
        this.isOpen = false;
    }

    toggle() {
        if (this.isOpen) this.close();
        else this.open();
    }

    filter(query) {
        const q = query.trim().toLowerCase();
        if (!q) {
            this.filteredItems = [...this.items];
        } else {
            this.filteredItems = this.items.filter(item =>
                item.title.toLowerCase().includes(q) ||
                item.category.toLowerCase().includes(q)
            );
        }
        this.selectedIndex = 0;
        this.renderList();
    }

    renderList() {
        const listEl = document.getElementById('cmd-palette-results');
        if (!listEl) return;

        if (!this.filteredItems.length) {
            listEl.innerHTML = `<div class="cmd-empty">NO MATCHING RECON MODULES OR ACTIONS FOUND.</div>`;
            return;
        }

        listEl.innerHTML = this.filteredItems.map((item, idx) => `
            <div class="cmd-item ${idx === this.selectedIndex ? 'selected' : ''}" data-idx="${idx}" onclick="window.cmdPalette.executeIndex(${idx})">
                <div class="cmd-item-left">
                    <span class="cmd-item-tag">${item.tag || '[MOD]'}</span>
                    <div>
                        <div class="cmd-item-title">${item.title}</div>
                        <div class="cmd-item-cat">${item.category}</div>
                    </div>
                </div>
                ${item.shortcut ? `<span class="cmd-item-shortcut">${item.shortcut}</span>` : ''}
            </div>
        `).join('');

        const selectedEl = listEl.children[this.selectedIndex];
        if (selectedEl) selectedEl.scrollIntoView({ block: 'nearest' });
    }

    handleKeyDown(e) {
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            this.selectedIndex = (this.selectedIndex + 1) % this.filteredItems.length;
            this.renderList();
            if (window.tacticalAudio) window.tacticalAudio.playClick(800, 0.02);
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            this.selectedIndex = (this.selectedIndex - 1 + this.filteredItems.length) % this.filteredItems.length;
            this.renderList();
            if (window.tacticalAudio) window.tacticalAudio.playClick(800, 0.02);
        } else if (e.key === 'Enter') {
            e.preventDefault();
            this.executeIndex(this.selectedIndex);
        }
    }

    executeIndex(idx) {
        const item = this.filteredItems[idx];
        if (!item) return;

        this.close();

        if (item.action) {
            item.action();
        } else if (item.id && window.switchTab) {
            window.switchTab(item.id, item.title.split('//')[0].trim());
        }

        if (window.tacticalAudio) {
            window.tacticalAudio.playModuleLaunch();
        }
    }
}

window.cmdPalette = new CommandPalette();
