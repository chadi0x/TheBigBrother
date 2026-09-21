/* ============================================================
   BIG BROTHER V7.0 — UNIFIED API CLIENT & REVERSE PROXY BRIDGE
   Guarantees zero-desync routing to FastAPI backend (port 8000).
   Intercepts all internal queries and enforces client-side CORS
   compliance and explicit status/error formatting.
   ============================================================ */

(function() {
    // Phase 3: Dynamic API Base URL Detection
    const API_BASE = (() => {
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

    // Preserve native fetch
    const _nativeFetch = window._nativeFetch || window.fetch;
    window._nativeFetch = _nativeFetch;

    // Transparent Proxy Interceptor: rewrite any relative /api/ routes to API_BASE
    window.fetch = function(resource, init) {
        if (typeof resource === 'string' && resource.startsWith('/api/')) {
            const base = window.API_BASE || '';
            if (base) {
                resource = `${base}${resource}`;
            }
        }
        return _nativeFetch.call(this, resource, init);
    };

    /**
     * Unified client-side fetch helper with explicit HTTP status and error reporting.
     * @param {string} endpoint - Relative API route (e.g. '/api/modules/chain_tracer') or full URL.
     * @param {RequestInit} [options={}] - Standard fetch configuration.
     * @returns {Promise<Response>}
     */
    window.nexusFetch = async function(endpoint, options = {}) {
        let url = endpoint;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            const base = window.API_BASE || '';
            if (base) {
                url = `${base}${url.startsWith('/') ? '' : '/'}${url}`;
            }
        }

        const headers = {
            'Accept': 'application/json',
            ...(options.headers || {})
        };

        if (options.body && !(options.body instanceof FormData) && !headers['Content-Type']) {
            headers['Content-Type'] = 'application/json';
        }

        let resp;
        try {
            resp = await _nativeFetch(url, {
                ...options,
                headers
            });
        } catch (err) {
            const targetHost = window.API_BASE || (window.location.origin || 'http://127.0.0.1:8000');
            const errorMsg = `[NETWORK ERROR] Could not reach FastAPI backend at ${targetHost}. Ensure server is running. (${err.message})`;
            const networkError = new Error(errorMsg);
            networkError.isNetworkError = true;
            networkError.originalError = err;
            throw networkError;
        }

        if (!resp.ok) {
            let serverErrorMsg = `HTTP ${resp.status}: ${resp.statusText || 'Server Error'}`;
            try {
                const errData = await resp.json();
                if (errData.detail) {
                    if (typeof errData.detail === 'string') {
                        serverErrorMsg = `HTTP ${resp.status}: ${errData.detail}`;
                    } else if (Array.isArray(errData.detail)) {
                        serverErrorMsg = `HTTP ${resp.status}: ` + errData.detail.map(d => `${d.loc ? d.loc.slice(-1)[0] + ': ' : ''}${d.msg}`).join(', ');
                    } else {
                        serverErrorMsg = `HTTP ${resp.status}: ${JSON.stringify(errData.detail)}`;
                    }
                } else if (errData.error) {
                    serverErrorMsg = `HTTP ${resp.status}: ${errData.error}`;
                } else if (errData.message) {
                    serverErrorMsg = `HTTP ${resp.status}: ${errData.message}`;
                }
            } catch {
                try {
                    const text = await resp.text();
                    if (text) serverErrorMsg = `HTTP ${resp.status}: ${text.slice(0, 160)}`;
                } catch {}
            }
            const httpError = new Error(serverErrorMsg);
            httpError.status = resp.status;
            httpError.response = resp;
            throw httpError;
        }

        return resp;
    };

    // Alias for developer ergonomics
    window.apiFetch = window.nexusFetch;
})();
