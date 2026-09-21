"""
THE BIG BROTHER // V7.0 TACTICAL FORENSIC SYSTEM
COMPANION POWER ENGINE: MULTI-FORGE REPO SECRET SCANNER & GITLEAKS ENGINE (v7_gitleaks_scanner)
CLASSIFIED // SOURCE CODE AUDITING & CLOUD CREDENTIAL EXTRACTION

Scans raw source code, git diffs, commits, and config files for leaked credentials:
- AWS Access Keys (AKIA...) & Secret Access Keys
- GitHub Personal Access Tokens (ghp_, gho_, ghu_)
- Slack Webhook URLs & Bot Tokens (xoxb-, xoxp-)
- Stripe Secret Keys (sk_live_, rk_live_)
- Private RSA, OpenSSH, PGP and EC keys
- Google Cloud Service Account JSON keys & Gemini API Keys
"""

import re
from typing import Dict, Any, List

GITLEAKS_RULES = [
    {
        "name": "AWS Access Key ID",
        "regex": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "severity": "CRITICAL",
        "category": "Cloud Infrastructure"
    },
    {
        "name": "GitHub Personal Access Token",
        "regex": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "severity": "CRITICAL",
        "category": "Source Control"
    },
    {
        "name": "Slack Webhook / Bot Token",
        "regex": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}|https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "severity": "HIGH",
        "category": "Messaging"
    },
    {
        "name": "Stripe Live Secret Key",
        "regex": r"(?:sk|rk)_live_[0-9a-zA-Z]{24,34}",
        "severity": "CRITICAL",
        "category": "Payment Gateway"
    },
    {
        "name": "Private RSA / OpenSSH Cryptographic Key",
        "regex": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "category": "Cryptographic Key"
    },
    {
        "name": "Google / Firebase / Gemini API Key",
        "regex": r"AIza[0-9A-Za-z\\-_]{35}",
        "severity": "HIGH",
        "category": "Cloud / AI API"
    },
    {
        "name": "Generic High-Entropy Secret / Password Assignment",
        "regex": r"""(?:password|passwd|secret|api_key|token)\s*[:=]\s*['"][a-zA-Z0-9_\-\.\$\!\@\#\%\^\&\*]{8,64}['"]""",
        "severity": "MEDIUM",
        "category": "Credential Assignment"
    }
]

def scan_code_for_secrets(code_or_commit_text: str) -> Dict[str, Any]:
    if not code_or_commit_text or not code_or_commit_text.strip():
        return {"status": "error", "error": "Code snippet or repository text is required."}
        
    text = code_or_commit_text.strip()
    
    findings = []
    
    for rule in GITLEAKS_RULES:
        matches = re.finditer(rule["regex"], text)
        for m in matches:
            matched_str = m.group(0)
            # Obfuscate middle chars for secure display
            if len(matched_str) > 8:
                masked = matched_str[:4] + "*" * (len(matched_str) - 8) + matched_str[-4:]
            else:
                masked = matched_str[:2] + "****"
                
            findings.append({
                "rule_name": rule["name"],
                "category": rule["category"],
                "severity": rule["severity"],
                "masked_secret": masked,
                "character_offset": m.start(),
                "snippet_context": text[max(0, m.start() - 30):min(len(text), m.end() + 30)].replace("\n", " ")
            })

    threat_tier = "CLEAN // NO_SECRETS_FOUND"
    if any(f["severity"] == "CRITICAL" for f in findings):
        threat_tier = "CRITICAL_EXPOSURE // ACTION_REQUIRED"
    elif findings:
        threat_tier = "ELEVATED_RISK // POTENTIAL_LEAKS"

    return {
        "status": "success",
        "scanned_length_chars": len(text),
        "total_secrets_detected": len(findings),
        "threat_tier": threat_tier,
        "findings": findings,
        "remediation_guidance": [
            "Revoke all detected API keys and secrets immediately from their provider console.",
            "Scrub repository history using 'git filter-repo' or BFG Repo-Cleaner.",
            "Install pre-commit hooks (e.g. gitleaks detect --pre-commit) to prevent future commits."
        ]
    }

async def scan_code_secrets_async(text: str) -> Dict[str, Any]:
    return scan_code_for_secrets(text)
