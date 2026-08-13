"""
AI ANALYST — Cross-module orchestrator.
Takes a single target + auto-detected type, fans out to the relevant modules
in parallel, and synthesizes a unified threat profile with a 0-100 score and
narrative bullets. Pure heuristic synthesis — no external LLM required.
"""
import asyncio
import re

from the_big_brother.modules.phantom_id import phantom_id_search
from the_big_brother.modules.breach_vault import breach_vault_search
from the_big_brother.modules.sigint_sweep import sigint_sweep
from the_big_brother.modules.shadow_map import shadow_map_analyze
from the_big_brother.modules.domain_oracle import domain_oracle
from the_big_brother.modules.mail_tracer import mail_tracer
from the_big_brother.modules.code_hunter import code_hunter
from the_big_brother.modules.wayback_spectre import wayback_spectre
from the_big_brother.modules.paste_dragnet import paste_dragnet
from the_big_brother.modules.digital_footprint import run_holehe


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.IGNORECASE)
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
USERNAME_RE = re.compile(r"^@?[a-z0-9_.-]{2,32}$", re.IGNORECASE)


def detect_type(target: str) -> str:
    t = target.strip()
    if EMAIL_RE.match(t):
        return "email"
    if IP_RE.match(t):
        return "ip"
    if DOMAIN_RE.match(t):
        return "domain"
    if USERNAME_RE.match(t):
        return "username"
    return "unknown"


async def _safe(coro, label):
    try:
        return label, await coro
    except Exception as e:
        return label, {"error": str(e)}


async def ai_analyst(target: str, mode: str = "auto") -> dict:
    target = target.strip()
    if not target:
        return {"error": "target required"}

    detected = detect_type(target) if mode == "auto" else mode
    if detected == "unknown":
        return {"error": "Could not classify target. Try email, domain, IP, or username."}

    plan = {
        "email": ["mail_tracer", "breach", "holehe", "paste"],
        "username": ["phantom", "code_hunter", "paste"],
        "domain": ["domain_oracle", "shadow_map", "wayback", "sigint", "paste"],
        "ip": ["shadow_map"],
    }[detected]

    coros = []
    if "phantom" in plan:
        coros.append(_safe(phantom_id_search(target.lstrip("@")), "phantom"))
    if "breach" in plan:
        coros.append(_safe(breach_vault_search(target, "email"), "breach"))
    if "holehe" in plan:
        coros.append(_safe(run_holehe(target), "holehe"))
    if "shadow_map" in plan:
        coros.append(_safe(shadow_map_analyze(target), "shadow_map"))
    if "domain_oracle" in plan:
        coros.append(_safe(domain_oracle(target), "domain_oracle"))
    if "mail_tracer" in plan:
        coros.append(_safe(mail_tracer(target), "mail_tracer"))
    if "code_hunter" in plan:
        coros.append(_safe(code_hunter(target.lstrip("@")), "code_hunter"))
    if "wayback" in plan:
        coros.append(_safe(wayback_spectre(target), "wayback"))
    if "sigint" in plan:
        coros.append(_safe(sigint_sweep(target), "sigint"))
    if "paste" in plan:
        coros.append(_safe(paste_dragnet(target), "paste"))

    results = dict(await asyncio.gather(*coros))

    findings = []
    score = 0

    p = results.get("phantom") or {}
    if p.get("found"):
        findings.append(f"Found on {p.get('found')}/{p.get('total_checked')} platforms — risk {p.get('risk_score')}")
        score += min(30, p.get("risk_score", 0) // 3)

    b = results.get("breach") or {}
    if b.get("breach_count"):
        findings.append(f"Exposed in {b.get('breach_count')} breaches · {b.get('total_records_exposed', 0):,} records")
        score += min(35, b.get("breach_count", 0) * 4)
    if b.get("pwned"):
        findings.append(f"Password seen {b.get('count', 0):,} times in HaveIBeenPwned")
        score += 30

    s = results.get("shadow_map") or {}
    if s.get("threat_score"):
        findings.append(f"Threat score {s.get('threat_score')} · {s.get('threat_level')}")
        score += min(30, s.get("threat_score", 0) // 3)

    d = results.get("domain_oracle") or {}
    if d.get("score") is not None:
        findings.append(f"Domain hygiene {d.get('score')}/100 — SPF/DMARC/DKIM/headers averaged")
        score += max(0, (100 - d.get("score", 100)) // 4)

    m = results.get("mail_tracer") or {}
    if m.get("trust_level"):
        findings.append(f"Email trust: {m.get('trust_level')} ({m.get('trust_score')}/100)")
        if m.get("flags", {}).get("disposable"):
            score += 15
        if not m.get("flags", {}).get("deliverable"):
            score += 10

    h = results.get("holehe") or {}
    if isinstance(h, dict) and h.get("found_on"):
        findings.append(f"Email registered on {len(h.get('found_on'))} platforms")
        score += min(15, len(h.get("found_on")) * 2)

    c = results.get("code_hunter") or {}
    if c.get("login") and c.get("public_repos"):
        findings.append(f"GitHub: {c.get('public_repos')} repos · {c.get('total_stars', 0)} stars · {len(c.get('commit_emails', []))} commit emails harvested")
        if c.get("commit_emails"):
            score += 10

    w = results.get("wayback") or {}
    if w.get("total_snapshots"):
        findings.append(f"Wayback: {w.get('total_snapshots'):,} snapshots · {w.get('sensitive_count', 0)} sensitive paths flagged")
        score += min(20, w.get("sensitive_count", 0))

    pst = results.get("paste") or {}
    if pst.get("total_hits"):
        critical = sum(1 for r in pst.get("results", []) if r.get("severity") == "CRITICAL")
        findings.append(f"Pastes: {pst.get('total_hits')} hits ({critical} flagged critical)")
        score += min(25, critical * 5)

    sig = results.get("sigint") or {}
    if sig.get("total"):
        findings.append(f"Sigint: {sig.get('total')} mentions across feeds")

    score = max(0, min(100, score))
    verdict = (
        "CRITICAL" if score >= 75 else
        "HIGH" if score >= 50 else
        "MODERATE" if score >= 25 else
        "LOW"
    )

    if not findings:
        findings.append("No notable signals detected across configured modules.")

    return {
        "target": target,
        "detected_type": detected,
        "modules_run": list(results.keys()),
        "risk_score": score,
        "verdict": verdict,
        "findings": findings,
        "raw": results,
    }
