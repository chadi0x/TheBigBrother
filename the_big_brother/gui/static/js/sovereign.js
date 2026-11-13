/* ============================================================================
   THE BIG BROTHER // VX.1 SOVEREIGN — ARSENAL UI + UNIVERSAL RESULT RENDERER
   - Dynamic 24-tool registry / form builder
   - Premium intelligence envelope renderer (findings, score ring, data tables)
   - MutationObserver that elevates every legacy .result-deck
   ========================================================================== */

(function () {
    'use strict';

    const ICONS = {
        globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>',
        certificate: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="18" height="14" rx="2"/><path d="M7 7h10M7 11h6"/><circle cx="16" cy="18" r="3"/><path d="M14 21l-1 2 3-1 3 1-1-2"/></svg>',
        radar: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/><path d="M12 12l7-4"/></svg>',
        shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>',
        wall: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="5" width="18" height="14" rx="1"/><path d="M3 10h18M3 15h18M8 5v5M16 5v5M6 10v5M14 10v5M10 15v4M18 15v4"/></svg>',
        pin: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 10c0 7-9 12-9 12S3 17 3 10a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>',
        cloud: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.5 19a4.5 4.5 0 0 0 .5-8.97A6 6 0 0 0 6.3 9.5 4.5 4.5 0 0 0 7 19h10.5z"/></svg>',
        'file-warning': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M12 11v5M12 18.5v.5"/></svg>',
        link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10 13a5 5 0 0 0 7.5.5l2-2a5 5 0 0 0-7-7l-1.5 1.5"/><path d="M14 11a5 5 0 0 0-7.5-.5l-2 2a5 5 0 0 0 7 7l1.5-1.5"/></svg>',
        key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3M17 6l2 2M14 9l2 2"/></svg>',
        lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
        user: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="8" r="4"/><path d="M4 21v-1a7 7 0 0 1 14 0v1"/></svg>',
        bug: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="6" y="7" width="12" height="13" rx="6"/><path d="M12 7V4M8 10H4M20 10h-4M8 16H4M20 16h-4M9 4l1 3M15 4l-1 3"/></svg>',
        crosshair: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="8"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4"/><circle cx="12" cy="12" r="2"/></svg>',
        car: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M5 17h14M6 17l-1-4 2-5h10l2 5-1 4"/><circle cx="8" cy="18" r="2"/><circle cx="16" cy="18" r="2"/></svg>',
        card: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20M6 15h4"/></svg>',
        at: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 0 0 5 0v-1a9 9 0 1 0-3 7"/></svg>',
        message: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15a4 4 0 0 1-4 4H8l-5 3V7a4 4 0 0 1 4-4h10a4 4 0 0 1 4 4z"/><path d="M8 10h8M8 14h5"/></svg>',
        discord: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 6a13 13 0 0 1 8 0l2 3a12 12 0 0 1 1 8l-3 2-2-3H10l-2 3-3-2a12 12 0 0 1 1-8z"/><circle cx="9" cy="13" r="1"/><circle cx="15" cy="13" r="1"/></svg>',
        send: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4z"/></svg>',
        gauge: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 19a9 9 0 1 1 16 0"/><path d="M12 13l4-4"/><circle cx="12" cy="14" r="1.5"/></svg>',
        eye: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
        graph: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="5" cy="6" r="2"/><circle cx="19" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><path d="M7 6h10M6.5 7.8l4.2 8.4M17.5 7.8l-4.2 8.4"/></svg>',
        package: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 8l-9-5-9 5 9 5 9-5z"/><path d="M3 8v8l9 5 9-5V8M12 13v8"/></svg>',
        code: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
        fingerprint: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 4a8 8 0 0 1 8 8M4 12a8 8 0 0 1 8-8M7 12a5 5 0 0 1 10 0M10 12a2 2 0 0 1 4 0v3a3 3 0 0 1-3 3M7 15v2M12 22a7 7 0 0 0 7-7"/></svg>',
        users: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="9" cy="8" r="4"/><path d="M2 21v-1a7 7 0 0 1 14 0v1M17 4a4 4 0 0 1 0 8M22 21v-1a6 6 0 0 0-4-5.6"/></svg>',
        default: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polygon points="12 2 22 8 22 16 12 22 2 16 2 8 12 2"/><path d="M12 22V12M2 8l10 4 10-4"/></svg>'
    };

    const state = {
        registry: null,
        tools: [],
        categories: [],
        filter: 'all',
        query: '',
        activeId: null,
        lastResult: null,
        loading: false,
    };

    // ------------------------------------------------------------------ utils
    function esc(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function humanize(key) {
        return String(key || '')
            .replace(/_/g, ' ')
            .replace(/([a-z])([A-Z])/g, '$1 $2')
            .replace(/\b\w/g, c => c.toUpperCase());
    }

    function riskColor(score) {
        const n = Number(score) || 0;
        if (n >= 70) return '#FF6B4A';
        if (n >= 35) return '#E8C87A';
        return '#5EEAD4';
    }

    function fmtTime(ms) {
        const n = Number(ms) || 0;
        return n >= 1000 ? (n / 1000).toFixed(2) + 's' : n + 'ms';
    }

    function copyText(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text);
        }
        const el = document.createElement('textarea');
        el.value = text;
        document.body.appendChild(el);
        el.select();
        document.execCommand('copy');
        el.remove();
        return Promise.resolve();
    }

    function toast(message, kind) {
        let host = document.getElementById('vx-toasts');
        if (!host) {
            host = document.createElement('div');
            host.id = 'vx-toasts';
            host.className = 'vx-toasts';
            document.body.appendChild(host);
        }
        const el = document.createElement('div');
        el.className = 'vx-toast ' + (kind || '');
        el.textContent = message;
        host.appendChild(el);
        setTimeout(() => {
            el.style.opacity = '0';
            el.style.transform = 'translateY(8px)';
            el.style.transition = 'all .25s ease';
            setTimeout(() => el.remove(), 260);
        }, 3200);
    }

    function download(name, text, type) {
        const blob = new Blob([text], { type: type || 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 2000);
    }

    // --------------------------------------------------------------- arsenal UI
    function toolById(id) {
        return state.tools.find(t => t.id === id) || null;
    }

    function categoryName(id) {
        const c = state.categories.find(x => x.id === id);
        return c ? c.name : humanize(id);
    }

    function renderHero() {
        const tools = state.tools.length;
        const categories = state.categories.length;
        const sources = new Set();
        state.tools.forEach(t => (t.sources || []).forEach(s => sources.add(s)));
        return `
            <div class="vx-hero">
                <div class="vx-hero-eyebrow"><span class="engine-pulse-dot"></span> VX.1 SOVEREIGN // THE ARSENAL</div>
                <h1>Twenty-four new engines.<br><em>One intelligence surface.</em></h1>
                <p>
                    A keyless, high-signal expansion of The Big Brother. Every engine returns a structured
                    intelligence envelope with a risk grade, severity-ranked findings and a navigable evidence
                    model — rendered by the same premium result surface across the entire platform.
                </p>
                <div class="vx-hero-stats">
                    <div class="vx-stat"><b class="gold">${tools}</b><span>New engines</span></div>
                    <div class="vx-stat"><b class="jade">${categories}</b><span>Disciplines</span></div>
                    <div class="vx-stat"><b class="ice">${sources.size}</b><span>Public sources</span></div>
                    <div class="vx-stat"><b>0</b><span>API keys required</span></div>
                    <div class="vx-stat"><b>76</b><span>Total engines</span></div>
                </div>
            </div>`;
    }

    function renderFilters() {
        const filters = [`<button class="vx-filter ${state.filter === 'all' ? 'active' : ''}" data-filter="all">ALL ENGINES</button>`]
            .concat(state.categories.map(c => `<button class="vx-filter ${state.filter === c.id ? 'active' : ''}" data-filter="${esc(c.id)}">${esc(c.name.toUpperCase())}</button>`));
        return `
            <div class="vx-toolbar">
                ${filters.join('')}
                <input id="vx-tool-search" class="vx-search" type="search" placeholder="Filter engines, sources, capabilities..." value="${esc(state.query)}">
            </div>`;
    }

    function renderToolCard(tool) {
        const active = state.activeId === tool.id ? 'is-active' : '';
        return `
            <article class="vx-tool-card ${active}" data-tool-id="${esc(tool.id)}" tabindex="0" role="button" aria-label="Open ${esc(tool.name)}">
                <div class="vx-tool-top">
                    <div class="vx-tool-icon">${ICONS[tool.icon] || ICONS.default}</div>
                    <span class="vx-tool-tag">${esc(tool.tag || 'VX')}</span>
                </div>
                <h3 class="vx-tool-name">${esc(tool.name)}</h3>
                <p class="vx-tool-desc">${esc(tool.description)}</p>
                <div class="vx-tool-foot">
                    <span class="vx-tool-cat">${esc(categoryName(tool.category))}</span>
                    <span class="vx-tool-launch">OPEN ENGINE <span aria-hidden="true">→</span></span>
                </div>
            </article>`;
    }

    function visibleTools() {
        const q = state.query.trim().toLowerCase();
        return state.tools.filter(t => {
            if (state.filter !== 'all' && t.category !== state.filter) return false;
            if (!q) return true;
            return [t.name, t.short, t.description, t.tag, categoryName(t.category), (t.sources || []).join(' ')]
                .join(' ').toLowerCase().includes(q);
        });
    }

    function renderGrid() {
        const tools = visibleTools();
        return `
            <div class="vx-tool-grid" id="vx-tool-grid">
                ${tools.length ? tools.map(renderToolCard).join('') : `<div class="vx-empty" style="grid-column:1/-1;">NO ENGINES MATCH THIS FILTER.</div>`}
            </div>`;
    }

    function renderRunner(tool) {
        if (!tool) {
            return `<div class="vx-empty" style="margin-top:16px;">SELECT AN ENGINE TO CONFIGURE A RUN.</div>`;
        }
        const fields = (tool.fields || []).map(f => {
            const isTextarea = f.type === 'textarea';
            const isPassword = f.type === 'password';
            const input = isTextarea
                ? `<textarea id="vx-field-${esc(f.name)}" name="${esc(f.name)}" placeholder="${esc(f.placeholder || '')}" ${f.required ? 'required' : ''} autocomplete="${esc(f.autocomplete || 'off')}"></textarea>`
                : `<input id="vx-field-${esc(f.name)}" name="${esc(f.name)}" type="${isPassword ? 'password' : (f.type === 'number' ? 'number' : 'text')}" placeholder="${esc(f.placeholder || '')}" ${f.required ? 'required' : ''} autocomplete="${esc(f.autocomplete || 'off')}" spellcheck="false">`;
            return `
                <div class="vx-runner-field" style="${isTextarea ? 'flex-basis:100%;' : ''}">
                    <label for="vx-field-${esc(f.name)}">${esc(f.label)}</label>
                    ${input}
                    ${f.hint ? `<div class="vx-hint">${esc(f.hint)}</div>` : ''}
                </div>`;
        }).join('');
        return `
            <div class="vx-runner vx-runner-anchor" id="vx-runner">
                <div class="vx-runner-header">
                    <div class="vx-runner-title">
                        <div class="vx-tool-icon">${ICONS[tool.icon] || ICONS.default}</div>
                        <div>
                            <h3>${esc(tool.name)}</h3>
                            <p>${esc(tool.description)}</p>
                        </div>
                    </div>
                    <div class="vx-runner-tools">
                        <span class="badge gold">${esc(tool.tag || 'VX')}</span>
                        <button class="btn-tactical-xs" id="vx-close-runner">CLOSE</button>
                    </div>
                </div>
                <div class="vx-runner-body">
                    <form class="vx-runner-form" id="vx-runner-form" data-tool="${esc(tool.id)}">
                        ${fields}
                        <div class="vx-runner-tools">
                            <button class="btn-tactical" type="submit" id="vx-run-btn">${esc(tool.run_label || 'RUN ENGINE')}</button>
                        </div>
                    </form>
                    <div class="vx-runner-meta">
                        ${(tool.sources || []).map(s => `<span>${esc(s)}</span>`).join('')}
                        <span>KEYLESS</span>
                        <span>STRUCTURED ENVELOPE</span>
                    </div>
                    <div id="vx-result-host"></div>
                </div>
            </div>`;
    }

    function renderArsenalShell() {
        const host = document.getElementById('vx-arsenal');
        if (!host) return;
        host.innerHTML = renderHero() + renderFilters() + renderGrid() + renderRunner(toolById(state.activeId));
        bindArsenalEvents();
        if (state.lastResult && state.activeId) {
            const resultHost = document.getElementById('vx-result-host');
            if (resultHost) resultHost.innerHTML = renderEnvelope(state.lastResult);
        }
    }

    function bindArsenalEvents() {
        const host = document.getElementById('vx-arsenal');
        if (!host) return;
        host.querySelectorAll('.vx-filter').forEach(btn => {
            btn.addEventListener('click', () => {
                state.filter = btn.dataset.filter;
                renderArsenalShell();
            });
        });
        const search = document.getElementById('vx-tool-search');
        if (search) {
            search.addEventListener('input', () => {
                state.query = search.value;
                const grid = document.getElementById('vx-tool-grid');
                const tools = visibleTools();
                if (grid) {
                    grid.innerHTML = tools.length ? tools.map(renderToolCard).join('') : `<div class="vx-empty" style="grid-column:1/-1;">NO ENGINES MATCH THIS FILTER.</div>`;
                    bindCards();
                }
            });
        }
        bindCards();
        const form = document.getElementById('vx-runner-form');
        if (form) form.addEventListener('submit', onRunSubmit);
        const close = document.getElementById('vx-close-runner');
        if (close) close.addEventListener('click', () => {
            state.activeId = null;
            state.lastResult = null;
            renderArsenalShell();
        });
    }

    function bindCards() {
        document.querySelectorAll('#vx-arsenal [data-tool-id]').forEach(card => {
            const open = () => selectTool(card.dataset.toolId);
            card.addEventListener('click', open);
            card.addEventListener('keydown', e => {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); }
            });
        });
    }

    function selectTool(id) {
        state.activeId = id;
        state.lastResult = null;
        renderArsenalShell();
        const runner = document.getElementById('vx-runner');
        if (runner) {
            setTimeout(() => runner.scrollIntoView({ behavior: 'smooth', block: 'start' }), 40);
            setTimeout(() => {
                const input = runner.querySelector('input, textarea');
                if (input) input.focus({ preventScroll: true });
            }, 220);
        }
        if (window.tacticalAudio && window.tacticalAudio.playClick) {
            try { window.tacticalAudio.playClick(940, 0.03); } catch (e) {}
        }
    }

    async function onRunSubmit(event) {
        event.preventDefault();
        const form = event.currentTarget;
        const toolId = form.dataset.tool;
        const tool = toolById(toolId);
        if (!tool || state.loading) return;
        const payload = {};
        new FormData(form).forEach((v, k) => { payload[k] = v; });
        const target = payload.target || payload.query || '';
        if (!String(target).trim()) {
            toast('Input required before execution.', 'error');
            return;
        }
        state.loading = true;
        const btn = document.getElementById('vx-run-btn');
        const resultHost = document.getElementById('vx-result-host');
        if (btn) {
            btn.disabled = true;
            btn.dataset.label = btn.textContent;
            btn.innerHTML = '<span class="spinner-pulse"></span> EXECUTING…';
        }
        if (resultHost) resultHost.innerHTML = `<div class="tactical-loading" style="margin-top:16px;"><span class="loading-scanline"></span><span class="spinner-pulse"></span> ENGINE ${esc(tool.short)} DISPATCHED — CORRELATING LIVE SOURCES…</div>`;
        const started = performance.now();
        try {
            const fetchImpl = window.nexusFetch || window.fetch;
            const resp = await fetchImpl('/api/arsenal/' + encodeURIComponent(toolId), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            if (!resp.ok) {
                let detail = `HTTP ${resp.status}`;
                try { const err = await resp.json(); detail = err.detail || err.error || detail; } catch (e) {}
                throw new Error(detail);
            }
            const data = await resp.json();
            data._client_elapsed_ms = Math.round(performance.now() - started);
            state.lastResult = data;
            if (resultHost) resultHost.innerHTML = renderEnvelope(data);
            if (window.threatMatrix) {
                try {
                    const targetValue = data.target || target;
                    window.threatMatrix.setTarget(targetValue);
                    (data.findings || []).slice(0, 8).forEach(f => {
                        const sev = String(f.severity || 'info').toLowerCase();
                        const points = { critical: 18, high: 11, medium: 6, low: 2, info: 0 }[sev] || 0;
                        if (points > 0) {
                            window.threatMatrix.registerFinding(
                                'arsenal_' + toolId,
                                'VX // ' + tool.short,
                                'vx_arsenal',
                                points,
                                f.title || (tool.name + ' finding'),
                                sev
                            );
                        }
                    });
                } catch (e) {}
            }
            toast(`${tool.short} complete — risk ${data.risk_score ?? '?'} / 100`, 'success');
        } catch (err) {
            const message = err && err.message ? err.message : 'Unknown engine failure';
            if (resultHost) {
                resultHost.innerHTML = `
                    <div class="vx-result">
                        <div class="vx-result-head">
                            <div class="vx-score-ring" style="--vx-score:100;--vx-color:#FF6B4A;"><div class="vx-score-inner"><b>!</b><span>FAULT</span></div></div>
                            <div class="vx-result-headline">
                                <div class="vx-result-kicker"><span>${esc(tool.short)}</span><span>//</span><span>UPSTREAM DIAGNOSTIC</span></div>
                                <h2>Engine did not complete</h2>
                                <p>${esc(message)}</p>
                            </div>
                        </div>
                    </div>`;
            }
            toast(message, 'error');
        } finally {
            state.loading = false;
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = esc(btn.dataset.label || 'RUN ENGINE');
            }
        }
    }

    // ---------------------------------------------------------- result renderer
    function severityCounts(findings) {
        const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        (findings || []).forEach(f => {
            const s = String(f.severity || 'info').toLowerCase();
            if (counts[s] !== undefined) counts[s] += 1;
        });
        return counts;
    }

    function renderFinding(f) {
        const sev = String(f.severity || 'info').toLowerCase();
        const ev = f.evidence != null ? (typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence)) : '';
        return `
            <div class="vx-finding ${esc(sev)}">
                <span class="vx-chip ${esc(sev)}">${esc(sev.toUpperCase())}</span>
                <div class="vx-finding-main">
                    <div class="vx-finding-title">${esc(f.title || 'Finding')}</div>
                    ${f.detail ? `<div class="vx-finding-detail">${esc(f.detail)}</div>` : ''}
                    ${ev ? `<div class="vx-finding-evidence">${esc(ev.length > 700 ? ev.slice(0, 700) + '…' : ev)}</div>` : ''}
                    ${f.recommendation ? `<div class="vx-finding-rec">${esc(f.recommendation)}</div>` : ''}
                </div>
            </div>`;
    }

    function isPrimitive(v) {
        return v == null || ['string', 'number', 'boolean'].includes(typeof v);
    }

    function shortValue(v) {
        if (v == null) return '—';
        if (typeof v === 'boolean') return v ? 'TRUE' : 'FALSE';
        if (typeof v === 'number') return Number.isInteger(v) ? String(v) : String(Math.round(v * 1000) / 1000);
        if (typeof v === 'string') return v.length > 240 ? v.slice(0, 240) + '…' : v;
        try { return JSON.stringify(v); } catch (e) { return String(v); }
    }

    function valueClass(key, value) {
        const k = String(key || '').toLowerCase();
        const s = shortValue(value).toLowerCase();
        if (['true', 'yes', 'present', 'valid', 'clean', 'clear', 'enforced', 'secure', 'verified', 'ok', 'success'].some(x => s === x || s.includes('verified'))) return 'good';
        if (['false', 'no', 'missing', 'invalid', 'expired', 'none', 'not_found', 'unknown'].some(x => s === x || s.includes('missing'))) return 'warn';
        if (k.includes('risk') || k.includes('critical') || k.includes('vuln') || k.includes('exposed')) return Number(value) > 0 ? 'bad' : 'good';
        return '';
    }

    function renderKV(obj) {
        return Object.entries(obj).map(([k, v]) => `
            <div class="vx-kv">
                <span>${esc(humanize(k))}</span>
                <b class="${valueClass(k, v)}">${esc(shortValue(v))}</b>
            </div>`).join('');
    }

    function columnsFor(rows) {
        const seen = [];
        for (const row of rows.slice(0, 25)) {
            if (!row || typeof row !== 'object') continue;
            for (const key of Object.keys(row)) {
                if (!seen.includes(key) && seen.length < 8) seen.push(key);
            }
        }
        return seen;
    }

    function renderTable(rows) {
        const cols = columnsFor(rows);
        if (!cols.length) return '';
        return `
            <div class="vx-data-table-wrap">
                <table class="vx-data-table">
                    <thead><tr>${cols.map(c => `<th>${esc(humanize(c))}</th>`).join('')}</tr></thead>
                    <tbody>
                        ${rows.slice(0, 60).map(row => `<tr>${cols.map(c => `<td>${esc(shortValue(row && row[c]))}</td>`).join('')}</tr>`).join('')}
                    </tbody>
                </table>
            </div>`;
    }

    function renderList(items) {
        if (!items.length) return '';
        if (items.every(isPrimitive)) {
            return `<div class="vx-tag-list">${items.slice(0, 90).map(v => `<span class="vx-tag">${esc(shortValue(v))}</span>`).join('')}</div>`;
        }
        if (items.every(v => v && typeof v === 'object' && !Array.isArray(v))) {
            return renderTable(items);
        }
        return `<div class="vx-list">${items.slice(0, 40).map(v => `
            <div class="vx-list-row">
                <span class="mono">${esc(shortValue(v))}</span>
            </div>`).join('')}</div>`;
    }

    function renderDataSection(key, value, depth) {
        if (value == null || value === '' || (Array.isArray(value) && value.length === 0)) return '';
        if (isPrimitive(value)) {
            return `<div class="vx-kv"><span>${esc(humanize(key))}</span><b>${esc(shortValue(value))}</b></div>`;
        }
        if (Array.isArray(value)) {
            return `
                <div class="vx-data-card" style="grid-column:1/-1;">
                    <h4>${esc(humanize(key))} <span style="color:var(--text-faint);font-weight:400;">// ${value.length}</span></h4>
                    ${renderList(value)}
                </div>`;
        }
        if (typeof value === 'object') {
            const entries = Object.entries(value);
            const primitiveOnly = entries.every(([, v]) => isPrimitive(v));
            if (primitiveOnly) {
                return `<div class="vx-data-card"><h4>${esc(humanize(key))}</h4>${renderKV(value)}</div>`;
            }
            return `
                <div class="vx-data-card" style="grid-column:1/-1;">
                    <h4>${esc(humanize(key))}</h4>
                    <div class="vx-data-grid">${entries.map(([k, v]) => renderDataSection(k, v, depth + 1)).join('')}</div>
                </div>`;
        }
        return '';
    }

    function renderData(data) {
        if (!data || typeof data !== 'object') return '';
        const entries = Object.entries(data);
        if (!entries.length) return '';
        return `<div class="vx-data-grid">${entries.map(([k, v]) => renderDataSection(k, v, 0)).join('')}</div>`;
    }

    function renderEnvelope(result) {
        if (!result || typeof result !== 'object') {
            return `<div class="vx-empty">EMPTY ENGINE RESPONSE.</div>`;
        }
        if (result.status === 'error') {
            return `
                <div class="vx-result">
                    <div class="vx-result-head">
                        <div class="vx-score-ring" style="--vx-score:100;--vx-color:#FF6B4A;"><div class="vx-score-inner"><b>!</b><span>FAULT</span></div></div>
                        <div class="vx-result-headline">
                            <div class="vx-result-kicker"><span>${esc(result.tool || 'ENGINE')}</span><span>//</span><span>DIAGNOSTIC</span></div>
                            <h2>Engine returned an error</h2>
                            <p>${esc(result.error || result.summary || 'Unknown failure')}</p>
                        </div>
                    </div>
                </div>`;
        }
        const risk = Number(result.risk_score ?? result.score ?? 0);
        const color = riskColor(risk);
        const findings = Array.isArray(result.findings) ? result.findings : [];
        const counts = severityCounts(findings);
        const tool = toolById(result.tool) || {};
        const title = tool.name || humanize(result.tool || 'Intelligence Report');
        const tier = result.risk_tier || (risk >= 70 ? 'CRITICAL' : risk >= 35 ? 'ELEVATED' : 'NOMINAL');
        const grade = result.grade || '—';
        const elapsed = result._client_elapsed_ms || result.elapsed_ms;
        const target = result.target || '';

        const chips = Object.entries(counts)
            .filter(([, n]) => n > 0)
            .map(([sev, n]) => `<span class="vx-chip ${sev}">${String(sev).toUpperCase()} ${n}</span>`)
            .join('');

        const dataHtml = renderData(result.data || {});
        const iocHtml = (result.iocs || []).length
            ? `<div class="vx-panel"><div class="vx-panel-head"><span>Extracted indicators</span><span>${(result.iocs || []).length} IOC</span></div><div class="vx-panel-body"><div class="vx-tag-list">${(result.iocs || []).slice(0, 120).map(i => `<span class="vx-tag ${i.type === 'ip' ? 'jade' : i.type === 'cve' ? 'ember' : 'gold'}">${esc(i.type || 'ioc')}: ${esc(i.value)}</span>`).join('')}</div></div></div>`
            : '';
        const notesHtml = (result.notes || []).length
            ? `<div class="vx-panel"><div class="vx-panel-head"><span>Operator notes</span></div><div class="vx-panel-body"><ul style="margin:0;padding-left:16px;color:var(--text-secondary);font-size:11px;line-height:1.8;">${(result.notes || []).map(n => `<li>${esc(n)}</li>`).join('')}</ul></div></div>`
            : '';
        const rawJson = JSON.stringify(result, null, 2);

        return `
            <div class="vx-result" data-vx-tool="${esc(result.tool || '')}">
                <div class="vx-result-head">
                    <div class="vx-score-ring" style="--vx-score:${Math.max(0, Math.min(100, risk))};--vx-color:${color};">
                        <div class="vx-score-inner"><b style="color:${color};">${risk}</b><span>Risk / 100</span></div>
                    </div>
                    <div class="vx-result-headline">
                        <div class="vx-result-kicker">
                            <span>${esc(title)}</span><span>//</span><span>${esc(tier)}</span><span>//</span><span>GRADE ${esc(grade)}</span>
                            ${elapsed ? `<span>//</span><span>${esc(fmtTime(elapsed))}</span>` : ''}
                        </div>
                        <h2>${esc(target || title)}</h2>
                        <p>${esc(result.summary || 'Engine completed.')}</p>
                    </div>
                    <div class="vx-result-actions">
                        <button class="btn-tactical-xs" data-vx-action="copy">COPY JSON</button>
                        <button class="btn-tactical-xs" data-vx-action="download">EXPORT JSON</button>
                    </div>
                </div>
                <div class="vx-result-body">
                    ${findings.length ? `
                        <div class="vx-panel">
                            <div class="vx-panel-head">
                                <span>Severity-ranked findings</span>
                                <span class="vx-sev-counts">${chips || '<span class="vx-chip info">NONE</span>'}</span>
                            </div>
                            <div class="vx-panel-body"><div class="vx-findings">${findings.map(renderFinding).join('')}</div></div>
                        </div>` : `
                        <div class="vx-panel">
                            <div class="vx-panel-head"><span>Findings</span></div>
                            <div class="vx-panel-body"><div class="vx-empty">No findings were emitted by this engine.</div></div>
                        </div>`}
                    ${dataHtml ? `<div class="vx-panel"><div class="vx-panel-head"><span>Structured intelligence model</span><span>LIVE DATA</span></div><div class="vx-panel-body">${dataHtml}</div></div>` : ''}
                    ${iocHtml}
                    ${notesHtml}
                    <div class="vx-panel">
                        <div class="vx-panel-head">
                            <span>Raw envelope</span>
                            <button class="btn-tactical-xs" data-vx-action="toggle-raw">TOGGLE</button>
                        </div>
                        <div class="vx-panel-body" data-vx-raw hidden>
                            <pre class="vx-json">${esc(rawJson)}</pre>
                        </div>
                    </div>
                </div>
            </div>`;
    }

    // Global delegated actions for VX results
    document.addEventListener('click', function (event) {
        const actionBtn = event.target.closest('[data-vx-action]');
        if (!actionBtn) return;
        const action = actionBtn.getAttribute('data-vx-action');
        const resultEl = actionBtn.closest('.vx-result');
        if (action === 'copy' && state.lastResult) {
            copyText(JSON.stringify(state.lastResult, null, 2)).then(() => toast('Envelope copied to clipboard.', 'success'));
        } else if (action === 'download' && state.lastResult) {
            const tool = state.lastResult.tool || 'intel';
            download(`VX_${tool}_${Date.now()}.json`, JSON.stringify(state.lastResult, null, 2));
            toast('Envelope exported.', 'success');
        } else if (action === 'toggle-raw' && resultEl) {
            const raw = resultEl.querySelector('[data-vx-raw]');
            if (raw) raw.hidden = !raw.hidden;
        }
    });

    // ------------------------------------------------- elevate legacy results
    function elevateResultDeck(deck) {
        if (!deck || deck.dataset.vxEnhanced === '1' || deck.classList.contains('vx-enhanced-result')) return;
        deck.dataset.vxEnhanced = '1';
        deck.classList.add('vx-enhanced-result');
        const bar = document.createElement('div');
        bar.className = 'vx-result-toolbar';
        bar.innerHTML = `<span>VX INTELLIGENCE SURFACE</span>
            <button class="btn-tactical-xs" data-vx-legacy="copy">COPY TEXT</button>
            <button class="btn-tactical-xs" data-vx-legacy="collapse">COLLAPSE</button>`;
        const first = deck.firstElementChild;
        if (first) deck.insertBefore(bar, first);
        else deck.appendChild(bar);
        bar.addEventListener('click', e => {
            const btn = e.target.closest('[data-vx-legacy]');
            if (!btn) return;
            if (btn.dataset.vxLegacy === 'copy') {
                copyText(deck.innerText || '').then(() => toast('Result text copied.', 'success'));
            } else {
                deck.classList.toggle('vx-collapsed');
                btn.textContent = deck.classList.contains('vx-collapsed') ? 'EXPAND' : 'COLLAPSE';
            }
        });
    }

    const observer = new MutationObserver(mutations => {
        for (const m of mutations) {
            for (const node of m.addedNodes) {
                if (!(node instanceof HTMLElement)) continue;
                if (node.classList && node.classList.contains('result-deck')) elevateResultDeck(node);
                if (node.querySelectorAll) node.querySelectorAll('.result-deck').forEach(elevateResultDeck);
            }
        }
    });

    // ------------------------------------------------------- command palette
    function injectPaletteTools() {
        if (!window.cmdPalette || !Array.isArray(window.cmdPalette.items) || !state.tools.length) return;
        const existing = new Set(window.cmdPalette.items.map(i => i.id));
        state.tools.forEach(tool => {
            const id = 'arsenal:' + tool.id;
            if (existing.has(id)) return;
            window.cmdPalette.items.push({
                id,
                title: tool.name + ' // ' + tool.tag,
                category: 'VX ARSENAL',
                shortcut: 'VX',
                tag: tool.short,
                action: () => {
                    if (window.switchTab) window.switchTab('tab-arsenal', 'VX ARSENAL');
                    setTimeout(() => {
                        selectTool(tool.id);
                        const runner = document.getElementById('vx-runner');
                        if (runner) runner.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    }, 120);
                },
            });
        });
        window.cmdPalette.filteredItems = [...window.cmdPalette.items];
    }

    // ---------------------------------------------------------------- bootstrap
    async function loadArsenal() {
        const host = document.getElementById('vx-arsenal');
        if (!host) return;
        host.innerHTML = `<div class="vx-empty">SYNCHRONIZING VX ARSENAL REGISTRY…</div>`;
        try {
            const fetchImpl = window.nexusFetch || window.fetch;
            const resp = await fetchImpl('/api/arsenal/registry');
            if (!resp.ok) throw new Error(`Registry HTTP ${resp.status}`);
            const registry = await resp.json();
            state.registry = registry;
            state.tools = registry.tools || [];
            state.categories = registry.categories || [];
            renderArsenalShell();
            injectPaletteTools();
            if (window.updateModuleBadge) {
                try { window.updateModuleBadge('arsenal', state.tools.length); } catch (e) {}
            }
        } catch (err) {
            host.innerHTML = `
                <div class="vx-empty" style="line-height:2;">
                    VX ARSENAL REGISTRY UNAVAILABLE.<br>
                    <span style="color:var(--text-dim);">${esc(err.message || err)}</span><br>
                    <button class="btn-tactical-xs" onclick="window.vxReloadArsenal()">RETRY REGISTRY</button>
                </div>`;
        }
    }

    window.vxReloadArsenal = loadArsenal;
    window.vxSelectTool = selectTool;
    window.vxRunTool = function (toolId) {
        if (window.switchTab) window.switchTab('tab-arsenal', 'VX ARSENAL');
        setTimeout(() => selectTool(toolId), 150);
    };
    window.vxRenderEnvelope = renderEnvelope;
    window.vxToast = toast;

    // ---------------------------------------------------------- shell / layout
    function initVxShell() {
        document.querySelectorAll('#nav-dock .nav-item').forEach(item => {
            if (!item.title) {
                const label = item.querySelector('.nav-text');
                if (label) item.title = label.textContent.trim();
            }
            item.addEventListener('click', () => {
                if (document.body.classList.contains('vx-inspector-open')) {
                    window.vxToggleInspector(false);
                }
                if (document.body.classList.contains('vx-mobile-nav-open')) {
                    window.vxToggleMobileNav(false);
                }
            });
        });
        const clock = () => {
            const el = document.getElementById('vx-live-clock');
            if (!el) return;
            const now = new Date();
            el.textContent = now.toISOString().slice(11, 19) + ' UTC';
        };
        clock();
        setInterval(clock, 1000);

        const syncThreat = () => {
            const score = document.getElementById('threat-score-number')?.textContent || '10';
            const tier = document.getElementById('threat-tier-text')?.textContent || 'SECURE';
            const scoreEl = document.getElementById('vx-dash-threat');
            const tierEl = document.getElementById('vx-dash-tier');
            if (scoreEl) scoreEl.textContent = score;
            if (tierEl) tierEl.textContent = tier;
            const uptime = document.getElementById('cc-metric-uptime')?.textContent;
            const uptimeEl = document.getElementById('vx-dash-uptime');
            if (uptime && uptimeEl) uptimeEl.textContent = uptime;
        };
        setInterval(syncThreat, 1500);
        syncThreat();

        const refreshVitals = async () => {
            try {
                const fetchImpl = window.nexusFetch || window.fetch;
                const resp = await fetchImpl('/api/telemetry/health');
                if (!resp.ok) return;
                const d = await resp.json();
                const cpu = Number(d.cpu_percent || 0);
                const mem = Number(d.memory_percent || 0);
                const cpuBar = document.getElementById('vx-dash-cpu-bar');
                const memBar = document.getElementById('vx-dash-mem-bar');
                if (cpuBar) cpuBar.style.width = Math.max(3, Math.min(100, cpu)) + '%';
                if (memBar) memBar.style.width = Math.max(3, Math.min(100, mem)) + '%';
                const jobs = document.getElementById('vx-dash-jobs');
                if (jobs) jobs.textContent = d.active_jobs ?? 0;
            } catch (e) {}
        };
        refreshVitals();
        setInterval(refreshVitals, 5000);

        document.addEventListener('keydown', e => {
            if (e.key !== 'Escape') return;
            if (document.body.classList.contains('vx-inspector-open')) {
                window.vxToggleInspector(false);
            }
            if (document.body.classList.contains('vx-mobile-nav-open')) {
                window.vxToggleMobileNav(false);
            }
        });
    }

    window.vxToggleInspector = function (force) {
        const open = typeof force === 'boolean'
            ? force
            : !document.body.classList.contains('vx-inspector-open');
        document.body.classList.toggle('vx-inspector-open', open);
    };

    window.vxToggleMobileNav = function (force) {
        const open = typeof force === 'boolean'
            ? force
            : !document.body.classList.contains('vx-mobile-nav-open');
        if (open) {
            const rail = document.getElementById('nav-dock');
            if (rail) rail.classList.remove('collapsed');
            document.body.classList.remove('vx-nav-collapsed');
        }
        document.body.classList.toggle('vx-mobile-nav-open', open);
    };

    function init() {
        loadArsenal();
        initVxShell();
        observer.observe(document.body, { childList: true, subtree: true });
        document.querySelectorAll('.result-deck').forEach(elevateResultDeck);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
