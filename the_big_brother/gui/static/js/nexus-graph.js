/* ============================================================
   BIG BROTHER V7.0 — NEXUS GRAPH CANVAS (CYTOSCAPE.JS)
   Dynamic Military-Grade Relationship & Entity Correlation Graph.
   Zero-Mock Architecture: Generates real topological networks from
   live module scan results and the autonomous threat matrix.
   Restricted strictly to relationship-capable investigative modules.
   ============================================================ */

(function() {
    'use strict';

    // Modules/tabs with genuine relationship graph capabilities
    const GRAPH_CAPABLE_TABS = new Set([
        'tab-analyst',
        'tab-chaintracer',
        'tab-evmsol',
        'tab-breach',
        'tab-shadowclone',
        'tab-spidercrawl',
        'tab-network',
        'tab-codehunter',
        'tab-hudsonrock',
        'tab-telemetry',
        'tab-oracle',
        'tab-profiler'
    ]);

    // Live module scan results cache
    window.moduleScanRegistry = {};

    function cleanModuleId(id) {
        if (!id) return '';
        return id.toLowerCase().replace(/^tab-/, '').replace(/^mod_/, '').replace(/_/g, '');
    }

    window.recordModuleResult = function(moduleId, data, query) {
        if (!moduleId || !data) return;
        const key = cleanModuleId(moduleId);
        window.moduleScanRegistry[key] = {
            moduleId: key,
            rawId: moduleId,
            data: data,
            query: query || data.target || data.query || data.address || data.username || data.domain || '',
            timestamp: Date.now()
        };
        // Also map under raw ID
        window.moduleScanRegistry[moduleId] = window.moduleScanRegistry[key];

        // If Nexus Canvas is currently visible, refresh topology live
        if (window.currentMode === 'nexus' && window.nexusGraph) {
            const activeTab = window.activeTab || 'tab-home';
            const activeKey = cleanModuleId(activeTab);
            if (activeKey === key || (activeTab === 'tab-home' && key === 'analyst')) {
                window.nexusGraph.updateForTab(activeTab);
            }
        }
    };

    window.getModuleResult = function(moduleId) {
        const key = cleanModuleId(moduleId);
        return window.moduleScanRegistry[key] || window.moduleScanRegistry[moduleId] || null;
    };

    class NexusGraphController {
        constructor() {
            this.cy = null;
            this.containerId = 'nexus-graph-canvas';
            this.currentTopology = null;
            this.currentTabId = 'tab-home';
            this.layoutName = 'cose';
        }

        isGraphCapable(tabId) {
            if (!tabId) return false;
            return GRAPH_CAPABLE_TABS.has(tabId);
        }

        init() {
            const container = document.getElementById(this.containerId);
            if (!container || typeof cytoscape === 'undefined') return;
            // Render initial topology based on active tab or threat matrix
            this.updateForTab(window.activeTab || 'tab-home');
        }

        /**
         * Update and render the graph topology specifically for the given tab
         */
        updateForTab(tabId) {
            this.currentTabId = tabId || window.activeTab || 'tab-home';
            if (!this.isGraphCapable(this.currentTabId)) {
                return;
            }

            const topology = this.generateTopologyForTab(this.currentTabId);
            this.render(topology);
        }

        /**
         * Dynamically generates real Cytoscape nodes and edges from live scan data
         */
        generateTopologyForTab(tabId) {
            const cleanId = cleanModuleId(tabId);
            const cached = window.getModuleResult(cleanId);
            const targetQuery = this._detectTargetForTab(tabId, cached);

            switch (cleanId) {
                case 'home':
                case 'analyst':
                    return this._buildAnalystTopology(cached, targetQuery);

                case 'chaintracer':
                    return this._buildChainTracerTopology(cached, targetQuery);

                case 'evmsol':
                    return this._buildEvmSolTopology(cached, targetQuery);

                case 'breach':
                    return this._buildBreachTopology(cached, targetQuery);

                case 'shadowclone':
                    return this._buildShadowCloneTopology(cached, targetQuery);

                case 'spidercrawl':
                    return this._buildSpiderCrawlTopology(cached, targetQuery);

                case 'network':
                    return this._buildNetworkTopology(cached, targetQuery);

                case 'hudsonrock':
                    return this._buildHudsonRockTopology(cached, targetQuery);

                case 'codehunter':
                    return this._buildCodeHunterTopology(cached, targetQuery);

                case 'telemetry':
                    return this._buildTelemetryTopology(cached, targetQuery);

                case 'ransom':
                    return this._buildRansomTopology(cached, targetQuery);

                case 'footprint':
                    return this._buildFootprintTopology(cached, targetQuery);

                case 'mailtracer':
                    return this._buildMailTracerTopology(cached, targetQuery);

                case 'oracle':
                    return this._buildOracleTopology(cached, targetQuery);

                case 'profiler':
                    return this._buildProfilerTopology(cached, targetQuery);

                default:
                    return this._createStandbyTopology(targetQuery, tabId.replace('tab-', '').toUpperCase(), 'Awaiting targeted forensic scan.');
            }
        }

        _detectTargetForTab(tabId, cached) {
            if (cached && cached.query) return cached.query;
            
            // Query active input values from DOM
            const inputs = {
                'tab-chaintracer': 'chaintracer-target',
                'tab-breach': 'breach-query',
                'tab-shadowclone': 'shadowclone-username',
                'tab-spidercrawl': 'spidercrawl-target',
                'tab-network': 'network-domain',
                'tab-hudsonrock': 'hudsonrock-query',
                'tab-codehunter': 'codehunter-target',
                'tab-evmsol': 'evmsol-target',
                'tab-telemetry': 'telemetry-target',
                'tab-ransom': 'ransom-target',
                'tab-footprint': 'footprint-query',
                'tab-mailtracer': 'mailtracer-query',
                'tab-oracle': 'oracle-domain',
                'tab-profiler': 'profiler-username'
            };

            const inputId = inputs[tabId];
            if (inputId) {
                const el = document.getElementById(inputId);
                if (el && el.value && el.value.trim()) {
                    return el.value.trim();
                }
            }

            if (window.threatMatrix && window.threatMatrix.target && window.threatMatrix.target !== 'UNASSESSED TARGET') {
                return window.threatMatrix.target;
            }

            return 'AWAITING TARGET';
        }

        _createStandbyTopology(target, title, instruction) {
            const rootLabel = target || 'STANDBY TARGET';
            return {
                title: title,
                scopeText: `SCOPE: ${title} // ${rootLabel} (STANDBY)`,
                elements: {
                    nodes: [
                        {
                            data: {
                                id: 'root_target',
                                label: rootLabel,
                                type: 'target',
                                risk: 'NOMINAL',
                                meta: `Active investigation target for ${title}.`
                            }
                        },
                        {
                            data: {
                                id: 'standby_guide',
                                label: 'EXECUTE SCAN TO MAP TOPOLOGY',
                                type: 'standby',
                                risk: 'INFO',
                                meta: instruction || 'Run module scan to populate live forensic nodes and relationship vectors.'
                            }
                        }
                    ],
                    edges: [
                        {
                            data: {
                                source: 'root_target',
                                target: 'standby_guide',
                                label: 'READY'
                            }
                        }
                    ]
                }
            };
        }

        /* ── MODULE SPECIFIC REAL TOPOLOGY BUILDERS ───────────────────────── */

        _buildAnalystTopology(cached, target) {
            const d = cached ? cached.data : null;
            if (d && d.graph_topology && d.graph_topology.nodes && d.graph_topology.nodes.length > 0) {
                return {
                    title: 'AI ANALYST CORTEX',
                    scopeText: `SCOPE: AI ANALYST // ${d.target || target} (${d.graph_topology.nodes.length} NODES, ${d.graph_topology.edges.length} EDGES)`,
                    elements: d.graph_topology
                };
            }

            // Synthesize from active window.threatMatrix if findings have been registered
            if (window.threatMatrix && window.threatMatrix.ledger && window.threatMatrix.ledger.length > 0) {
                const nodes = [];
                const edges = [];
                const rootTarget = window.threatMatrix.target || target || 'CORRELATION TARGET';
                const score = window.threatMatrix.score || 50;

                nodes.push({
                    data: {
                        id: 'root_target',
                        label: rootTarget,
                        type: 'target',
                        risk: score >= 70 ? 'CRITICAL' : score >= 30 ? 'HIGH' : 'NOMINAL',
                        meta: `Composite Target Threat Score: ${score}/100 [${score >= 70 ? 'CRITICAL' : 'ACTIVE MONITORING'}]`
                    }
                });

                const categories = {};
                window.threatMatrix.ledger.forEach((finding, idx) => {
                    const catKey = finding.sourceModule || finding.category || 'intel';
                    if (!categories[catKey]) {
                        categories[catKey] = `cat_${catKey}`;
                        nodes.push({
                            data: {
                                id: categories[catKey],
                                label: (finding.category || catKey).toUpperCase(),
                                type: 'category',
                                risk: 'ELEVATED',
                                meta: `Aggregated findings from module: ${catKey}`
                            }
                        });
                        edges.push({
                            data: {
                                source: 'root_target',
                                target: categories[catKey],
                                label: 'CORRELATION'
                            }
                        });
                    }

                    const fNodeId = `finding_${idx}`;
                    nodes.push({
                        data: {
                            id: fNodeId,
                            label: finding.label.length > 32 ? finding.label.slice(0, 30) + '...' : finding.label,
                            type: finding.severity === 'critical' ? 'threat' : 'finding',
                            risk: (finding.severity || 'high').toUpperCase(),
                            meta: `${finding.label} (+${finding.points} pts)`
                        }
                    });
                    edges.push({
                        data: {
                            source: categories[catKey],
                            target: fNodeId,
                            label: `+${finding.points} PTS`
                        }
                    });
                });

                return {
                    title: 'SYNTHESIS WAR-ROOM',
                    scopeText: `SCOPE: WAR-ROOM CORRELATION // ${rootTarget} (${nodes.length} NODES, ${edges.length} EDGES)`,
                    elements: { nodes, edges }
                };
            }

            return this._createStandbyTopology(target, 'COMMAND CENTER // AI ANALYST', 'Execute autonomous cross-module synthesis to generate relationship topology.');
        }

        _buildChainTracerTopology(cached, target) {
            const d = cached ? cached.data : null;
            if (!d || (!d.address && !d.target)) {
                return this._createStandbyTopology(target, 'CHAIN TRACER', 'Submit a wallet address (BTC/ETH/SOL/TRX) to map counterparty flows.');
            }

            const nodes = [];
            const edges = [];
            const addr = d.address || d.target;
            const shortAddr = addr.length > 14 ? `${addr.slice(0, 7)}...${addr.slice(-5)}` : addr;

            nodes.push({
                data: {
                    id: 'root_target',
                    label: shortAddr,
                    type: 'target',
                    risk: d.risk_score >= 70 ? 'CRITICAL' : d.risk_score >= 30 ? 'HIGH' : 'NOMINAL',
                    meta: `Chain: ${d.chain || 'CRYPTO'} | Balance: ${d.balance || 0} | USD: $${(d.usd_valuation || 0).toLocaleString()}`
                }
            });

            // Token holdings
            const tokens = d.token_balances || [];
            tokens.slice(0, 5).forEach((t, i) => {
                const id = `token_${i}`;
                nodes.push({
                    data: {
                        id: id,
                        label: `${t.symbol || 'TOKEN'}: ${t.balance || 0}`,
                        type: 'token',
                        risk: 'ELEVATED',
                        meta: `Contract: ${t.address || t.contract || 'ERC-20'}`
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: id, label: 'ASSET_HOLDING' }
                });
            });

            // Counterparty flow
            const counterparties = d.attributed_counterparties || [];
            counterparties.slice(0, 7).forEach((cp, i) => {
                const id = `cp_${i}`;
                const cpAddr = cp.address || `Counterparty-${i}`;
                const cpShort = cpAddr.length > 12 ? `${cpAddr.slice(0, 6)}...${cpAddr.slice(-4)}` : cpAddr;
                nodes.push({
                    data: {
                        id: id,
                        label: cp.label || cpShort,
                        type: cp.is_sanctioned ? 'hash' : cp.is_mixer ? 'wallet' : 'ip',
                        risk: cp.is_sanctioned ? 'CRITICAL' : cp.is_mixer ? 'HIGH' : 'MEDIUM',
                        meta: `Flow: ${cp.flow_type || 'Transfer'} | Address: ${cpAddr}`
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: id, label: cp.flow_type || 'COUNTERPARTY' }
                });
            });

            // Mixer & OFAC Warnings
            if (d.risk_matrix && (d.risk_matrix.mixer_proximity || d.risk_matrix.mixer_interaction)) {
                nodes.push({
                    data: {
                        id: 'warn_mixer',
                        label: 'WASABI / TORNADO HOP',
                        type: 'hash',
                        risk: 'CRITICAL',
                        meta: 'Direct interaction with cryptocurrency tumbling / privacy protocol'
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: 'warn_mixer', label: 'TUMBLER_INTERACTION' }
                });
            }

            if (d.risk_matrix && d.risk_matrix.ofac_sanction_match) {
                nodes.push({
                    data: {
                        id: 'warn_ofac',
                        label: 'OFAC SDN SANCTIONS MATCH',
                        type: 'hash',
                        risk: 'CRITICAL',
                        meta: 'Address listed on US Treasury OFAC Specially Designated Nationals sanctions database'
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: 'warn_ofac', label: 'OFAC_MATCH' }
                });
            }

            return {
                title: 'CHAIN TRACER FORENSICS',
                scopeText: `SCOPE: CHAIN TRACER // ${shortAddr} (${nodes.length} NODES, ${edges.length} EDGES)`,
                elements: { nodes, edges }
            };
        }

        _buildEvmSolTopology(cached, target) {
            const d = cached ? cached.data : null;
            if (!d || (!d.target && !d.address)) {
                return this._createStandbyTopology(target, 'EVM & SOLANA TRACER', 'Input address to map smart contract calls and token transfers.');
            }
            return this._buildChainTracerTopology(cached, target);
        }

        _buildBreachTopology(cached, target) {
            const d = cached ? cached.data : null;
            const email = (d && (d.query || d.email || d.target)) || (cached && cached.query) || target || 'TARGET_EMAIL';
            const breaches = (d && d.breaches) ? d.breaches : [];
            const pastes = (d && d.pastes) ? d.pastes : [];
            
            if (!d || (!breaches.length && !pastes.length && d.count === undefined && !d.status)) {
                return this._createStandbyTopology(email, 'BREACH VAULT', 'Check an email address to construct the credential breach exposure graph.');
            }

            const nodes = [];
            const edges = [];

            nodes.push({
                data: {
                    id: 'root_target',
                    label: email,
                    type: 'target',
                    risk: (d.threat_level === 'CRITICAL' || breaches.length > 3) ? 'CRITICAL' : (breaches.length > 0 ? 'HIGH' : 'NOMINAL'),
                    meta: `Exposures: ${breaches.length} breaches, ${pastes.length} pastes detected. Total records: ${(d.total_records_exposed || 0).toLocaleString()}`
                }
            });

            breaches.slice(0, 8).forEach((b, i) => {
                const bId = `breach_${i}`;
                const title = b.title || b.name || `Breach-${i}`;
                const pwn = b.pwn_count ? ` (${Number(b.pwn_count).toLocaleString()})` : '';
                nodes.push({
                    data: {
                        id: bId,
                        label: `${title}${pwn}`,
                        type: 'breach',
                        risk: b.severity || 'HIGH',
                        meta: `Breach Date: ${b.date || b.breach_date || 'Undisclosed'} | Domain: ${b.domain || 'N/A'}`
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: bId, label: 'LEAKED_IN' }
                });

                // Leaked data classes
                const classes = b.data_classes || [];
                classes.slice(0, 3).forEach((dc, j) => {
                    const dcId = `dc_${i}_${j}`;
                    const isPwd = dc.toLowerCase().includes('password') || dc.toLowerCase().includes('hash');
                    nodes.push({
                        data: {
                            id: dcId,
                            label: dc.toUpperCase(),
                            type: isPwd ? 'hash' : 'email',
                            risk: isPwd ? 'CRITICAL' : 'ELEVATED',
                            meta: `Exposed data class in ${title}`
                        }
                    });
                    edges.push({
                        data: { source: bId, target: dcId, label: 'EXPOSED_DATA' }
                    });
                });
            });

            // Pastes
            pastes.slice(0, 4).forEach((p, i) => {
                const pId = `paste_${i}`;
                nodes.push({
                    data: {
                        id: pId,
                        label: `PASTE: ${p.title || p.id || 'Paste Entry'}`,
                        type: 'hash',
                        risk: 'CRITICAL',
                        meta: `Source: ${p.source || 'Public Paste'} | Date: ${p.date || 'Active'}`
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: pId, label: 'PUBLIC_PASTE' }
                });
            });

            return {
                title: 'BREACH VAULT EXPOSURE',
                scopeText: `SCOPE: BREACH VAULT // ${email} (${nodes.length} NODES, ${edges.length} EDGES)`,
                elements: { nodes, edges }
            };
        }

        _buildShadowCloneTopology(cached, target) {
            const d = cached ? cached.data : null;
            const username = (d && (d.target || d.username)) || (cached && cached.query) || target || 'TARGET_USER';
            const profiles = (d && (d.profiles || d.discovered_profiles)) ? (d.profiles || d.discovered_profiles) : [];
            const clones = (d && d.active_clones) ? d.active_clones : [];

            if (!d || (!profiles.length && !clones.length && !d.summary && !d.target)) {
                return this._createStandbyTopology(username, 'SHADOW CLONE', 'Submit username to probe online enclaves and adversarial impersonator clones.');
            }

            const nodes = [];
            const edges = [];
            const rootLabel = `@${username.replace(/^@/, '')}`;

            nodes.push({
                data: {
                    id: 'root_target',
                    label: rootLabel,
                    type: 'target',
                    risk: d.threat_tier === 'CRITICAL_IMPERSONATION' ? 'CRITICAL' : (d.threat_score >= 25 ? 'HIGH' : 'NOMINAL'),
                    meta: `Persona Exposure Score: ${d.threat_score || 0}/100 | Discovered: ${profiles.length} accounts`
                }
            });

            // Discovered Verified Profiles
            profiles.slice(0, 10).forEach((p, i) => {
                const profId = `prof_${i}`;
                const plat = (p.platform || 'Platform').toUpperCase();
                nodes.push({
                    data: {
                        id: profId,
                        label: `${plat}: ${p.display_name || rootLabel}`,
                        type: 'profile',
                        risk: 'HIGH',
                        meta: `URL: ${p.url || 'N/A'}${p.bio ? ' | Bio: ' + p.bio : ''}`
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: profId, label: 'CONFIRMED_ENCLAVE' }
                });
            });

            // Adversarial Clone Mutations
            clones.slice(0, 8).forEach((c, i) => {
                const cloneId = `clone_${i}`;
                const cand = c.mutation || c.candidate || `clone_${i}`;
                const simVal = c.jaro_winkler_similarity || c.similarity || 0;
                const sim = simVal ? ` (${(simVal * 100).toFixed(0)}%)` : '';
                nodes.push({
                    data: {
                        id: cloneId,
                        label: `CLONE: @${cand}${sim}`,
                        type: 'clone',
                        risk: c.impersonation_risk === 'CRITICAL_CLONE' ? 'CRITICAL' : (c.risk_tier || 'HIGH'),
                        meta: `Platform: ${c.platform || 'Web'} | Status: ${c.impersonation_risk || 'Squatting candidate'}`
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: cloneId, label: 'ADVERSARY_CLONE' }
                });
            });

            return {
                title: 'SHADOW CLONE PERSONA',
                scopeText: `SCOPE: SHADOW CLONE // ${rootLabel} (${nodes.length} NODES, ${edges.length} EDGES)`,
                elements: { nodes, edges }
            };
        }

        _buildSpiderCrawlTopology(cached, target) {
            const d = cached ? cached.data : null;
            const targetUrl = (d && (d.target || d.url || d.domain)) || (cached && cached.query) || target || 'TARGET_URL';
            const secrets = (d && d.secrets_found) ? d.secrets_found : [];
            const emails = (d && d.emails) ? d.emails : [];
            const files = (d && (d.sensitive_files_found || d.files)) ? (d.sensitive_files_found || d.files) : [];
            const internalLinks = (d && (d.internal_links || d.discovered_urls)) ? (d.internal_links || d.discovered_urls) : [];

            if (!d || (!d.target && !d.url && !secrets.length && !emails.length && !internalLinks.length)) {
                return this._createStandbyTopology(targetUrl, 'WEB SPIDER', 'Crawl domain/URL to extract discovered endpoints, forms, emails, and secrets.');
            }

            const nodes = [];
            const edges = [];
            nodes.push({
                data: {
                    id: 'root_target',
                    label: targetUrl,
                    type: 'target',
                    risk: (secrets.length > 0) ? 'CRITICAL' : 'HIGH',
                    meta: `Surface Mapped: ${d.internal_links_count || internalLinks.length || 0} internal, ${d.external_links_count || 0} external endpoints.`
                }
            });

            // Discovered Secrets
            secrets.slice(0, 5).forEach((s, i) => {
                const secId = `sec_${i}`;
                nodes.push({
                    data: {
                        id: secId,
                        label: `SECRET: ${s.rule || s.type || 'Key'}`,
                        type: 'secret',
                        risk: 'CRITICAL',
                        meta: `High entropy credential token detected in source`
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: secId, label: 'EXPOSED_SECRET' }
                });
            });

            // Harvested Emails
            emails.slice(0, 5).forEach((e, i) => {
                const emId = `em_${i}`;
                const emailStr = typeof e === 'string' ? e : (e.email || 'email');
                nodes.push({
                    data: {
                        id: emId,
                        label: emailStr,
                        type: 'email',
                        risk: 'HIGH',
                        meta: 'Discovered in scraped DOM text/mailtos'
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: emId, label: 'HARVESTED_EMAIL' }
                });
            });

            // Sensitive URIs
            files.slice(0, 4).forEach((f, i) => {
                const fId = `sf_${i}`;
                const fPath = typeof f === 'string' ? f : (f.path || f.url || 'file');
                nodes.push({
                    data: {
                        id: fId,
                        label: `FILE: ${fPath}`,
                        type: 'domain',
                        risk: 'HIGH',
                        meta: 'Sensitive configuration or backup asset'
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: fId, label: 'DISCLOSED_ASSET' }
                });
            });

            // Discovered Endpoints
            internalLinks.slice(0, 5).forEach((l, i) => {
                const lId = `link_${i}`;
                const lStr = typeof l === 'string' ? l : (l.url || l.href || `Link-${i}`);
                nodes.push({
                    data: {
                        id: lId,
                        label: lStr.length > 25 ? lStr.slice(0, 22) + '...' : lStr,
                        type: 'domain',
                        risk: 'NOMINAL',
                        meta: `Discovered endpoint: ${lStr}`
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: lId, label: 'CRAWLED_URI' }
                });
            });

            return {
                title: 'SPIDER CRAWL RECON',
                scopeText: `SCOPE: SPIDER CRAWL // ${targetUrl} (${nodes.length} NODES, ${edges.length} EDGES)`,
                elements: { nodes, edges }
            };
        }

        _buildNetworkTopology(cached, target) {
            const d = cached ? cached.data : null;
            const host = (d && (d.domain || d.ip || d.target)) || (cached && cached.query) || target || 'TARGET_HOST';
            const ports = (d && (d.ports || d.open_ports)) ? (d.ports || d.open_ports) : [];

            if (!d || (!d.domain && !d.ip && !ports.length)) {
                return this._createStandbyTopology(host, 'NETWORK SCANNER', 'Scan host/IP to map open ports, banners, and perimeter topology.');
            }

            const nodes = [];
            const edges = [];

            nodes.push({
                data: {
                    id: 'root_target',
                    label: host,
                    type: 'target',
                    risk: 'HIGH',
                    meta: `Target host perimeter: ${host}`
                }
            });

            // IP / ASN node
            const ip = (d.geoip && d.geoip.ip) || d.ip || host;
            const asn = (d.geoip && d.geoip.asn) || 'ASN';
            nodes.push({
                data: {
                    id: 'node_ip',
                    label: `${ip} (${asn})`,
                    type: 'ip',
                    risk: 'ELEVATED',
                    meta: `Org: ${d.geoip?.org || 'N/A'} | Location: ${d.geoip?.city || ''} ${d.geoip?.country || ''}`
                }
            });
            edges.push({
                data: { source: 'root_target', target: 'node_ip', label: 'RESOLVES_TO' }
            });

            // Open Ports
            ports.slice(0, 8).forEach(p => {
                const pId = `port_${p.port}`;
                nodes.push({
                    data: {
                        id: pId,
                        label: `PORT ${p.port}: ${p.service || 'TCP'}`,
                        type: 'port',
                        risk: p.risk === 'HIGH' ? 'CRITICAL' : 'HIGH',
                        meta: `State: ${p.state || 'OPEN'} | Banner: ${p.banner || 'No banner returned'}`
                    }
                });
                edges.push({
                    data: { source: 'node_ip', target: pId, label: 'OPEN_PORT' }
                });
            });

            return {
                title: 'NETWORK PERIMETER',
                scopeText: `SCOPE: NETWORK SCAN // ${host} (${nodes.length} NODES, ${edges.length} EDGES)`,
                elements: { nodes, edges }
            };
        }

        _buildHudsonRockTopology(cached, target) {
            const d = cached ? cached.data : null;
            const q = (d && (d.query || d.domain || d.email || d.target)) || (cached && cached.query) || target || 'TARGET_ENTITY';
            const compromises = (d && (d.compromises || d.victims || d.stealers)) ? (d.compromises || d.victims || d.stealers) : [];

            if (!d || (!d.query && !d.domain && !d.email && !compromises.length && d.total_stealers === undefined)) {
                return this._createStandbyTopology(q, 'HUDSON ROCK INFOSTEALER', 'Query domain/email to map infostealer infections and compromised machines.');
            }

            const nodes = [];
            const edges = [];
            nodes.push({
                data: {
                    id: 'root_target',
                    label: q,
                    type: 'target',
                    risk: (d.is_compromised || compromises.length > 0) ? 'CRITICAL' : 'NOMINAL',
                    meta: `Status: ${(d.is_compromised || compromises.length > 0) ? 'COMPROMISED' : 'CLEAN'} | Total Stealers: ${d.total_stealers || compromises.length || 0}`
                }
            });

            compromises.slice(0, 6).forEach((c, i) => {
                const id = `inf_${i}`;
                nodes.push({
                    data: {
                        id: id,
                        label: `${c.malware_family || c.malware || 'STEALER'}: ${c.computer_name || 'PC-' + i}`,
                        type: 'malware',
                        risk: 'CRITICAL',
                        meta: `Date: ${c.date_compromised || 'Exfiltrated'} | OS: ${c.operating_system || c.os || 'Windows'}`
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: id, label: 'EXFILTRATED_SYSTEM' }
                });
            });

            if (d.total_credentials || d.total_compromised_credentials) {
                const credCount = d.total_credentials || d.total_compromised_credentials;
                nodes.push({
                    data: {
                        id: 'node_creds',
                        label: `${credCount} COMPROMISED CREDS`,
                        type: 'hash',
                        risk: 'CRITICAL',
                        meta: 'Extracted credentials stored in Cavalier infostealer database'
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: 'node_creds', label: 'LEAKED_PASSWORDS' }
                });
            }

            return {
                title: 'INFOSTEALER COMPROMISE',
                scopeText: `SCOPE: HUDSON ROCK // ${q} (${nodes.length} NODES, ${edges.length} EDGES)`,
                elements: { nodes, edges }
            };
        }

        _buildCodeHunterTopology(cached, target) {
            const d = cached ? cached.data : null;
            const targetUser = (d && (d.login || d.target || d.name)) || (cached && cached.query) || target || 'TARGET_DEVELOPER';
            const repos = (d && (d.top_repos || d.repositories || d.repos)) ? (d.top_repos || d.repositories || d.repos) : [];
            const emails = (d && (d.commit_emails || d.harvested_emails || d.emails)) ? (d.commit_emails || d.harvested_emails || d.emails) : [];

            if (!d || (!d.login && !d.target && !repos.length && !emails.length)) {
                return this._createStandbyTopology(targetUser, 'CODE HUNTER', 'Investigate GitHub developer to trace repositories, commit logs, and exposed secrets.');
            }

            const nodes = [];
            const edges = [];
            nodes.push({
                data: {
                    id: 'root_target',
                    label: `@${targetUser}`,
                    type: 'target',
                    risk: d.threat_level === 'CRITICAL' ? 'CRITICAL' : (d.threat_score >= 35 ? 'HIGH' : 'NOMINAL'),
                    meta: `Developer: ${d.name || targetUser} | Company: ${d.company || 'INDEPENDENT'} | Followers: ${d.followers || 0} / ${d.following || 0}`
                }
            });

            // Repositories
            repos.slice(0, 6).forEach((r, i) => {
                const rId = `repo_${i}`;
                const rName = r.name || `Repo-${i}`;
                const stars = (r.stars !== undefined && r.stars > 0) ? ` (★${r.stars})` : '';
                nodes.push({
                    data: {
                        id: rId,
                        label: `${rName}${stars}`,
                        type: 'domain',
                        risk: (r.stars > 50) ? 'HIGH' : 'MEDIUM',
                        meta: `Lang: ${r.language || 'N/A'} | ${(r.description || 'Repository').slice(0, 80)}`
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: rId, label: 'PUBLIC_REPO' }
                });
            });

            // Harvested commit author emails
            emails.slice(0, 5).forEach((m, i) => {
                const emId = `mail_${i}`;
                const emailStr = typeof m === 'string' ? m : (m.email || m.address || 'email');
                nodes.push({
                    data: {
                        id: emId,
                        label: emailStr,
                        type: 'email',
                        risk: 'CRITICAL',
                        meta: 'Disclosed in public git commit history author metadata'
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: emId, label: 'COMMIT_AUTHOR' }
                });
            });

            // Organizations
            const orgs = d.orgs || [];
            orgs.slice(0, 4).forEach((o, i) => {
                const oId = `org_${i}`;
                const oName = o.login || o.name || `Org-${i}`;
                nodes.push({
                    data: {
                        id: oId,
                        label: `ORG: ${oName}`,
                        type: 'category',
                        risk: 'ELEVATED',
                        meta: `Organization membership: ${oName}`
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: oId, label: 'MEMBER_OF' }
                });
            });

            // Languages stack
            const langs = d.languages || [];
            if (Array.isArray(langs) && langs.length > 0) {
                langs.slice(0, 4).forEach((l, i) => {
                    const lId = `lang_${i}`;
                    nodes.push({
                        data: {
                            id: lId,
                            label: `${l.name} (${l.percentage || 0}%)`,
                            type: 'token',
                            risk: 'NOMINAL',
                            meta: `Primary language: ${l.name} (${l.count || 0} repos)`
                        }
                    });
                    edges.push({
                        data: { source: 'root_target', target: lId, label: 'USES_TECH' }
                    });
                });
            }

            // Public SSH/GPG Keys
            const sshKeys = d.ssh_keys || [];
            if (sshKeys.length > 0) {
                nodes.push({
                    data: {
                        id: 'node_ssh',
                        label: `${sshKeys.length} PUBLIC SSH KEY(S)`,
                        type: 'hash',
                        risk: 'ELEVATED',
                        meta: 'SSH public key registered on GitHub profile'
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: 'node_ssh', label: 'AUTH_KEY' }
                });
            }

            return {
                title: 'GIT CODE RECON',
                scopeText: `SCOPE: CODE HUNTER // @${targetUser} (${nodes.length} NODES, ${edges.length} EDGES)`,
                elements: { nodes, edges }
            };
        }

        _buildTelemetryTopology(cached, target) {
            const d = cached ? cached.data : null;
            if (!d || !d.target) {
                return this._createStandbyTopology(target, 'TELEMETRY HUNTER', 'Audit website trackers and shared AdTech beacons to reveal sister properties.');
            }

            const nodes = [];
            const edges = [];
            nodes.push({
                data: {
                    id: 'root_target',
                    label: d.target,
                    type: 'target',
                    risk: 'HIGH',
                    meta: `Apex domain: ${d.target}`
                }
            });

            const beacons = d.beacons || d.tracking_beacons || [];
            beacons.slice(0, 5).forEach((b, i) => {
                const bId = `beacon_${i}`;
                nodes.push({
                    data: {
                        id: bId,
                        label: `TRACKER: ${b.tracker_id || b.id || 'AdTech'}`,
                        type: 'beacon',
                        risk: 'HIGH',
                        meta: `Vendor: ${b.vendor || 'Analytics/Tag Manager'}`
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: bId, label: 'SHARED_TRACKER' }
                });
            });

            const sisters = d.correlated_sister_domains || [];
            sisters.slice(0, 5).forEach((s, i) => {
                const sId = `sis_${i}`;
                nodes.push({
                    data: {
                        id: sId,
                        label: `SISTER: ${s.domain || s}`,
                        type: 'sister_domain',
                        risk: 'HIGH',
                        meta: `Correlated infrastructure sharing beacon: ${s.tracker_id || 'ID'}`
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: sId, label: 'SISTER_DOMAIN' }
                });
            });

            return {
                title: 'ADTECH TELEMETRY GRAPH',
                scopeText: `SCOPE: TELEMETRY // ${d.target} (${nodes.length} NODES, ${edges.length} EDGES)`,
                elements: { nodes, edges }
            };
        }

        _buildRansomTopology(cached, target) {
            const d = cached ? cached.data : null;
            if (!d || !d.target) {
                return this._createStandbyTopology(target, 'RANSOM DISCLOSE', 'Search organization across live darknet ransomware leak blogs.');
            }

            const nodes = [];
            const edges = [];
            nodes.push({
                data: {
                    id: 'root_target',
                    label: d.target,
                    type: 'target',
                    risk: d.is_listed_on_leak_sites ? 'CRITICAL' : 'NOMINAL',
                    meta: `Status: ${d.is_listed_on_leak_sites ? 'LISTED ON EXTORTION SITES' : 'NO KNOWN LISTINGS'}`
                }
            });

            const leaks = d.extortion_incidents || d.leaks || [];
            leaks.slice(0, 6).forEach((l, i) => {
                const lId = `cartel_${i}`;
                nodes.push({
                    data: {
                        id: lId,
                        label: `CARTEL: ${l.group_name || 'Ransom Group'}`,
                        type: 'cartel',
                        risk: 'CRITICAL',
                        meta: `Published: ${l.published_date || 'Active'} | Size: ${l.claimed_data_size || 'Undisclosed'}`
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: lId, label: 'EXTORTION_POST' }
                });
            });

            return {
                title: 'RANSOMWARE EXTORTION',
                scopeText: `SCOPE: RANSOM // ${d.target} (${nodes.length} NODES, ${edges.length} EDGES)`,
                elements: { nodes, edges }
            };
        }

        _buildFootprintTopology(cached, target) {
            const d = cached ? cached.data : null;
            if (!d || !d.query) {
                return this._createStandbyTopology(target, 'DIGITAL FOOTPRINT', 'Analyze domain perimeters and DNS zone mapping.');
            }

            const nodes = [];
            const edges = [];
            nodes.push({
                data: {
                    id: 'root_target',
                    label: d.query,
                    type: 'target',
                    risk: 'HIGH',
                    meta: `Recon surface for ${d.query}`
                }
            });

            const subs = d.subdomains || [];
            subs.slice(0, 6).forEach((s, i) => {
                const sId = `sub_${i}`;
                nodes.push({
                    data: {
                        id: sId,
                        label: s,
                        type: 'domain',
                        risk: 'MEDIUM',
                        meta: 'Discovered subdomain'
                    }
                });
                edges.push({
                    data: { source: 'root_target', target: sId, label: 'SUBDOMAIN' }
                });
            });

            return {
                title: 'DIGITAL FOOTPRINT',
                scopeText: `SCOPE: FOOTPRINT // ${d.query} (${nodes.length} NODES, ${edges.length} EDGES)`,
                elements: { nodes, edges }
            };
        }

        _buildMailTracerTopology(cached, target) {
            const d = cached ? cached.data : null;
            if (!d || !d.query) {
                return this._createStandbyTopology(target, 'MAIL TRACER', 'Audit mail servers and MX relay routes.');
            }
            const nodes = [{ data: { id: 'root_target', label: d.query, type: 'target', risk: 'HIGH', meta: 'Target Mail Host' } }];
            const edges = [];
            const mx = d.mx_records || [];
            mx.slice(0, 4).forEach((m, i) => {
                const mId = `mx_${i}`;
                nodes.push({ data: { id: mId, label: `MX: ${m.host || m}`, type: 'ip', risk: 'MEDIUM', meta: `Priority: ${m.priority || 10}` } });
                edges.push({ data: { source: 'root_target', target: mId, label: 'MX_RECORD' } });
            });
            return {
                title: 'MAIL RELAY TOPOLOGY',
                scopeText: `SCOPE: MAIL TRACER // ${d.query} (${nodes.length} NODES, ${edges.length} EDGES)`,
                elements: { nodes, edges }
            };
        }

        _buildOracleTopology(cached, target) {
            const d = cached ? cached.data : null;
            const dom = (d && (d.domain || d.target || d.query)) || (cached && cached.query) || target || 'TARGET_DOMAIN';
            const ns = (d && (d.nameservers || (d.dns && d.dns.NS))) ? (d.nameservers || (d.dns && d.dns.NS)) : [];
            const subs = (d && (d.subdomains || d.discovered_subdomains)) ? (d.subdomains || d.discovered_subdomains) : [];
            const mx = (d && (d.mx_records || (d.dns && d.dns.MX))) ? (d.mx_records || (d.dns && d.dns.MX)) : [];

            if (!d || (!d.domain && !d.whois && !ns.length && !subs.length)) {
                return this._createStandbyTopology(dom, 'DOMAIN ORACLE', 'WHOIS & DNS Entity Resolution.');
            }

            const nodes = [{
                data: {
                    id: 'root_target',
                    label: dom,
                    type: 'target',
                    risk: 'HIGH',
                    meta: `Domain: ${dom} | Registrar: ${d.registrar || (d.whois && d.whois.registrar) || 'N/A'}`
                }
            }];
            const edges = [];

            if (d.registrar || (d.whois && d.whois.registrar)) {
                const reg = d.registrar || d.whois.registrar;
                nodes.push({
                    data: {
                        id: 'node_reg',
                        label: `REG: ${reg}`,
                        type: 'domain',
                        risk: 'MEDIUM',
                        meta: `Registrar of record: ${reg}`
                    }
                });
                edges.push({ data: { source: 'root_target', target: 'node_reg', label: 'REGISTERED_VIA' } });
            }

            ns.slice(0, 4).forEach((s, i) => {
                const nsId = `ns_${i}`;
                const nsStr = typeof s === 'string' ? s : (s.host || s.target || 'NS');
                nodes.push({
                    data: {
                        id: nsId,
                        label: `NS: ${nsStr}`,
                        type: 'ip',
                        risk: 'MEDIUM',
                        meta: `Authoritative Nameserver: ${nsStr}`
                    }
                });
                edges.push({ data: { source: 'root_target', target: nsId, label: 'NAMESERVER' } });
            });

            subs.slice(0, 6).forEach((s, i) => {
                const sId = `sub_${i}`;
                const subStr = typeof s === 'string' ? s : (s.domain || s.name || 'sub');
                nodes.push({
                    data: {
                        id: sId,
                        label: `SUB: ${subStr}`,
                        type: 'domain',
                        risk: 'MEDIUM',
                        meta: `Discovered Subdomain: ${subStr}`
                    }
                });
                edges.push({ data: { source: 'root_target', target: sId, label: 'SUBDOMAIN' } });
            });

            mx.slice(0, 3).forEach((m, i) => {
                const mId = `mx_${i}`;
                const mStr = typeof m === 'string' ? m : (m.host || m.exchange || 'MX');
                nodes.push({
                    data: {
                        id: mId,
                        label: `MX: ${mStr}`,
                        type: 'email',
                        risk: 'MEDIUM',
                        meta: `Mail Exchanger: ${mStr}`
                    }
                });
                edges.push({ data: { source: 'root_target', target: mId, label: 'MAIL_EXCHANGER' } });
            });

            return {
                title: 'DOMAIN ORACLE WHOIS',
                scopeText: `SCOPE: ORACLE // ${dom} (${nodes.length} NODES, ${edges.length} EDGES)`,
                elements: { nodes, edges }
            };
        }

        _buildProfilerTopology(cached, target) {
            const d = cached ? cached.data : null;
            const targetUser = (d && (d.target || d.username)) || (cached && cached.query) || target || 'TARGET_USER';
            const results = (d && d.results) ? d.results.filter(r => (r.status === 'Found' || r.status === 'FOUND' || r.found)) : ((d && d.found_profiles) || []);

            if (!results.length) {
                return this._createStandbyTopology(targetUser, 'PROFILER CORE', 'Search 300+ platforms for username footprint.');
            }

            const nodes = [{
                data: {
                    id: 'root_target',
                    label: `@${targetUser.replace(/^@/, '')}`,
                    type: 'target',
                    risk: 'HIGH',
                    meta: `Profiler Subject: @${targetUser} | Total Matches: ${results.length}`
                }
            }];
            const edges = [];

            results.slice(0, 10).forEach((r, i) => {
                const pId = `prof_${i}`;
                const site = r.site || r.platform || 'Platform';
                nodes.push({
                    data: {
                        id: pId,
                        label: `${site}: CLAIMED`,
                        type: 'profile',
                        risk: 'HIGH',
                        meta: r.url || `Account verified on ${site}`
                    }
                });
                edges.push({ data: { source: 'root_target', target: pId, label: 'ACCOUNT_EXISTS' } });
            });

            return {
                title: 'PROFILER IDENTITY GRAPH',
                scopeText: `SCOPE: PROFILER // @${targetUser} (${nodes.length} NODES, ${edges.length} EDGES)`,
                elements: { nodes, edges }
            };
        }

        /* ── CYTOSCAPE RENDERING ENGINE ───────────────────────────────────── */

        render(topologyConfig) {
            const container = document.getElementById(this.containerId);
            if (!container || typeof cytoscape === 'undefined') return;

            const elements = topologyConfig.elements || topologyConfig;
            this.currentTopology = topologyConfig;

            // Update scope text badge
            const badge = document.getElementById('nexus-graph-scope-badge');
            if (badge && topologyConfig.scopeText) {
                badge.textContent = topologyConfig.scopeText.toUpperCase();
            }

            try {
                if (this.cy) {
                    this.cy.destroy();
                }

                this.cy = cytoscape({
                    container: container,
                    elements: elements,
                    style: [
                        {
                            selector: 'node',
                            style: {
                                'background-color': '#0D1117',
                                'border-width': 2,
                                'border-color': '#00F0FF',
                                'label': 'data(label)',
                                'color': '#EEF2FF',
                                'font-family': 'JetBrains Mono, monospace',
                                'font-size': '10px',
                                'text-valign': 'bottom',
                                'text-margin-y': 6,
                                'text-outline-width': 2,
                                'text-outline-color': '#06080C',
                                'width': 34,
                                'height': 34,
                                'transition-property': 'background-color, border-color, width, height',
                                'transition-duration': '0.2s'
                            }
                        },
                        {
                            selector: 'node[type="target"]',
                            style: {
                                'background-color': 'rgba(0, 240, 255, 0.25)',
                                'border-color': '#00F0FF',
                                'border-width': 3,
                                'width': 48,
                                'height': 48,
                                'font-size': '11px',
                                'font-weight': 'bold'
                            }
                        },
                        {
                            selector: 'node[type="category"]',
                            style: {
                                'background-color': 'rgba(99, 102, 241, 0.25)',
                                'border-color': '#6366F1',
                                'border-width': 2.5,
                                'width': 40,
                                'height': 40,
                                'font-size': '10px',
                                'font-weight': 'bold'
                            }
                        },
                        {
                            selector: 'node[type="email"]',
                            style: {
                                'background-color': 'rgba(157, 0, 255, 0.2)',
                                'border-color': '#9D00FF'
                            }
                        },
                        {
                            selector: 'node[type="breach"]',
                            style: {
                                'background-color': 'rgba(255, 42, 85, 0.25)',
                                'border-color': '#FF2A55',
                                'border-width': 2.5
                            }
                        },
                        {
                            selector: 'node[type="profile"]',
                            style: {
                                'background-color': 'rgba(217, 70, 239, 0.2)',
                                'border-color': '#D946EF'
                            }
                        },
                        {
                            selector: 'node[type="clone"]',
                            style: {
                                'background-color': 'rgba(249, 115, 22, 0.25)',
                                'border-color': '#F97316',
                                'border-width': 2.5
                            }
                        },
                        {
                            selector: 'node[type="hash"], node[type="secret"]',
                            style: {
                                'background-color': 'rgba(239, 68, 68, 0.25)',
                                'border-color': '#EF4444',
                                'border-width': 2.5
                            }
                        },
                        {
                            selector: 'node[type="malware"], node[type="threat"], node[type="cartel"]',
                            style: {
                                'background-color': 'rgba(220, 38, 38, 0.25)',
                                'border-color': '#DC2626',
                                'border-width': 2.5
                            }
                        },
                        {
                            selector: 'node[type="wallet"], node[type="token"]',
                            style: {
                                'background-color': 'rgba(255, 184, 0, 0.2)',
                                'border-color': '#FFB800'
                            }
                        },
                        {
                            selector: 'node[type="ip"], node[type="domain"], node[type="port"]',
                            style: {
                                'background-color': 'rgba(0, 255, 157, 0.2)',
                                'border-color': '#00FF9D'
                            }
                        },
                        {
                            selector: 'node[type="beacon"], node[type="sister_domain"]',
                            style: {
                                'background-color': 'rgba(234, 179, 8, 0.2)',
                                'border-color': '#EAB308'
                            }
                        },
                        {
                            selector: 'node[type="standby"]',
                            style: {
                                'background-color': 'rgba(148, 163, 184, 0.1)',
                                'border-color': '#94A3B8',
                                'border-style': 'dashed',
                                'border-width': 1.5,
                                'color': '#94A3B8'
                            }
                        },
                        {
                            selector: 'node:selected',
                            style: {
                                'border-color': '#FFFFFF',
                                'border-width': 3,
                                'shadow-blur': 15,
                                'shadow-color': '#00F0FF'
                            }
                        },
                        {
                            selector: 'edge',
                            style: {
                                'width': 1.6,
                                'line-color': 'rgba(0, 240, 255, 0.35)',
                                'target-arrow-color': '#00F0FF',
                                'target-arrow-shape': 'triangle',
                                'curve-style': 'bezier',
                                'label': 'data(label)',
                                'font-family': 'JetBrains Mono, monospace',
                                'font-size': '8px',
                                'color': '#7B87A8',
                                'text-rotation': 'autorotate',
                                'text-margin-y': -8
                            }
                        },
                        {
                            selector: 'edge:selected',
                            style: {
                                'width': 2.8,
                                'line-color': '#00F0FF',
                                'target-arrow-color': '#00F0FF'
                            }
                        }
                    ],
                    layout: {
                        name: this.layoutName,
                        animate: true,
                        animationDuration: 400,
                        padding: 50,
                        nodeRepulsion: 6500
                    }
                });

                this.cy.on('tap', 'node', (evt) => {
                    this._inspectNode(evt.target.data());
                });

                this.cy.on('tap', (evt) => {
                    if (evt.target === this.cy) {
                        this._clearInspectNode();
                    }
                });

            } catch (err) {
                console.warn('[NexusGraph] Render warning:', err);
            }
        }

        setLayout(name) {
            this.layoutName = name;
            if (!this.cy) return;
            const layout = this.cy.layout({
                name: name,
                animate: true,
                animationDuration: 400,
                padding: 50
            });
            layout.run();
        }

        resetView() {
            if (!this.cy) return;
            this.cy.fit(null, 50);
        }

        exportImage() {
            if (!this.cy) return;
            const png = this.cy.png({ bg: '#06080C', full: true, scale: 2 });
            const a = document.createElement('a');
            a.href = png;
            a.download = `NEXUS_GRAPH_${this.currentTabId}_${Date.now()}.png`;
            a.click();
        }

        _inspectNode(data) {
            const panel = document.getElementById('nexus-node-inspector');
            if (!panel) return;
            panel.classList.remove('hide');

            const riskColor = data.risk === 'CRITICAL' ? 'var(--neon-red)' :
                             data.risk === 'HIGH' ? 'var(--neon-amber)' :
                             data.risk === 'ELEVATED' ? 'var(--neon-purple)' : 'var(--neon-emerald)';

            panel.innerHTML = `
                <div class="inspector-card reveal">
                    <div class="inspector-header">
                        <div>
                            <span class="telemetry-tag">${data.type ? data.type.toUpperCase() : 'NODE'}</span>
                            <h4 class="inspector-title">${data.label}</h4>
                        </div>
                        <button class="btn-icon-xs" onclick="window.nexusGraph._clearInspectNode()">&times;</button>
                    </div>
                    <div class="inspector-body">
                        <div class="inspector-row">
                            <span class="dim">Threat Classification:</span>
                            <strong style="color:${riskColor};">${data.risk || 'UNCLASSIFIED'}</strong>
                        </div>
                        <div class="inspector-row">
                            <span class="dim">Node ID:</span>
                            <code>${data.id}</code>
                        </div>
                        <div class="inspector-meta">${data.meta || 'Forensic correlation confirmed via autonomous engine crawl.'}</div>
                    </div>
                    <div class="inspector-actions">
                        <button class="btn-tactical-xs" onclick="copyToClipboard('${data.label}', this)">COPY INDICATOR</button>
                        <button class="btn-tactical-xs cyan" onclick="window.nexusGraph.centerOnNode('${data.id}')">CENTER VIEW</button>
                    </div>
                </div>
            `;

            if (window.tacticalAudio && window.tacticalAudio.enabled) {
                window.tacticalAudio.playClick(1050, 0.04);
            }
        }

        _clearInspectNode() {
            const panel = document.getElementById('nexus-node-inspector');
            if (panel) {
                panel.classList.add('hide');
                panel.innerHTML = '';
            }
        }

        centerOnNode(nodeId) {
            if (!this.cy) return;
            const node = this.cy.getElementById(nodeId);
            if (node && node.length) {
                this.cy.animate({
                    center: { eles: node },
                    zoom: 1.8,
                    duration: 400
                });
            }
        }
    }

    window.NexusGraphController = NexusGraphController;
    window.nexusGraph = new NexusGraphController();

})();
