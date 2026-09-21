"""
THE BIG BROTHER // V7.0 TACTICAL FORENSIC SYSTEM
COMPANION POWER ENGINE: PARAM-MINER & OPENAPI / SWAGGER FUZZER (v7_param_miner)
CLASSIFIED // RED-TEAM ATTACK SURFACE MAPPING DIVISION

Probes target URLs and domains for hidden debug parameters, exposed administrative
flags, API documentation manifests, and reflection points:
- Swagger / OpenAPI manifest discovery (/swagger.json, /openapi.json, /api-docs, /v3/api-docs)
- Common debug/privileged query parameter injection test (?debug=1, ?admin=true, ?test=1, ?trace=1, ?env=prod)
- Reflection and status code differential analysis
- Unauthenticated API endpoint listing
"""

import asyncio
import json
import re
import ssl
import urllib.parse
import urllib.request
import urllib.error
from typing import Dict, Any, List

COMMON_DEBUG_PARAMS = [
    ("debug", "true"),
    ("test", "1"),
    ("admin", "1"),
    ("internal", "true"),
    ("env", "staging"),
    ("show_secrets", "1"),
    ("trace", "true"),
    ("dump", "1"),
    ("bypass", "1"),
    ("preview", "1")
]

API_DOC_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs",
    "/redoc",
    "/swagger-ui.html",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/swagger.json"
]

def _http_get_sync(req_url: str, timeout: float = 4.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BigBrotherSecurityResearch/7.0",
        "Accept": "*/*"
    }
    req = urllib.request.Request(req_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            content = resp.read()
            return resp.status, dict(resp.headers), content
    except urllib.error.HTTPError as he:
        try:
            content = he.read()
        except Exception:
            content = b""
        return he.code, dict(he.headers), content
    except Exception:
        return None, {}, b""

async def mine_parameters_and_api(target_url: str) -> Dict[str, Any]:
    if not target_url:
        return {"status": "error", "error": "Target URL is required."}
        
    url = target_url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    discovered_apis = []
    param_findings = []
    
    # 1. Baseline Request
    baseline_res = await asyncio.to_thread(_http_get_sync, url)
    baseline_status = baseline_res[0] or "UNREACHABLE"
    baseline_length = len(baseline_res[2])

    # 2. Check OpenAPI / Swagger Documentation paths
    async def check_path(path: str):
        probe_url = f"{base_origin.rstrip('/')}{path}"
        status, headers, content = await asyncio.to_thread(_http_get_sync, probe_url)
        if status == 200:
            content_type = headers.get("Content-Type", headers.get("content-type", "")).lower()
            is_json = "json" in content_type
            endpoints_count = 0
            title = "API Documentation"
            text = content.decode("utf-8", errors="ignore")
            
            if is_json:
                try:
                    data = json.loads(text)
                    title = data.get("info", {}).get("title", "API Spec")
                    paths = data.get("paths", {})
                    endpoints_count = len(paths)
                except Exception:
                    pass
            elif "swagger" in text.lower() or "openapi" in text.lower():
                title = "Swagger UI Portal"
            else:
                return None
                
            return {
                "path": path,
                "url": probe_url,
                "status": status,
                "title": title,
                "endpoints_uncovered": endpoints_count,
                "risk": "EXPOSED_API_DOCUMENTATION"
            }
        return None

    doc_tasks = [check_path(p) for p in API_DOC_PATHS]
    doc_results = await asyncio.gather(*doc_tasks, return_exceptions=True)
    for res in doc_results:
        if isinstance(res, dict) and res:
            discovered_apis.append(res)

    # 3. Fuzz Debug & Privileged Query Parameters (Differential Analysis)
    if baseline_status and baseline_status != "UNREACHABLE":
        async def fuzz_param(key: str, val: str):
            delimiter = "&" if "?" in url else "?"
            test_url = f"{url}{delimiter}{key}={val}"
            status, headers, content = await asyncio.to_thread(_http_get_sync, test_url)
            if status is None:
                return None
            len_diff = abs(len(content) - baseline_length)
            text = content.decode("utf-8", errors="ignore")
            
            is_interesting = False
            reason = ""
            if status != baseline_status:
                is_interesting = True
                reason = f"HTTP status code shifted from {baseline_status} to {status}"
            elif len_diff > (baseline_length * 0.15) and len_diff > 100:
                is_interesting = True
                reason = f"Body length differential delta of {len_diff} bytes"
            elif key in text and val in text:
                is_interesting = True
                reason = f"Parameter value reflected directly in body"

            if is_interesting:
                return {
                    "parameter": key,
                    "injected_value": val,
                    "probe_url": test_url,
                    "status": status,
                    "delta_reason": reason,
                    "severity": "HIGH_CONFIDENCE_PARAMETER_LEAK"
                }
            return None
                
        fuzz_tasks = [fuzz_param(k, v) for k, v in COMMON_DEBUG_PARAMS]
        fuzz_results = await asyncio.gather(*fuzz_tasks, return_exceptions=True)
        for f in fuzz_results:
            if isinstance(f, dict) and f:
                param_findings.append(f)

    return {
        "status": "success",
        "target": url,
        "base_origin": base_origin,
        "baseline": {
            "status": baseline_status,
            "content_length": baseline_length
        },
        "discovered_apis": discovered_apis,
        "param_findings": param_findings,
        "total_apis_found": len(discovered_apis),
        "total_anomalous_params": len(param_findings),
        "posture": "CRITICAL_EXPOSURE" if (discovered_apis and param_findings) else ("SUSPICIOUS" if (discovered_apis or param_findings) else "HARDENED_PERIMETER")
    }
