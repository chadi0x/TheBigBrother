"""
THE BIG BROTHER // V7.0 TACTICAL FORENSIC SYSTEM
COMPANION POWER ENGINE: RAW STEALER LOG & SESSION ARCHIVE PARSER (v7_stealer_parser)
CLASSIFIED // LAW ENFORCEMENT & THREAT INTEL TIER-1 USE ONLY

Parses raw infostealer logs (RedLine, Vidar, Lumma, Raccoon, MetaStealer, Stealc)
into structured forensic ledgers:
- Passwords (URL, Username, Password)
- Discord Tokens & Telegram Sessions
- Browser Cookies & Session Tokens
- Crypto Wallet Browser Extensions (MetaMask, Phantom, TronLink, Coinbase)
- Hardware & Machine Telemetry (HWID, GPU, RAM, Windows build)
"""

import re
import json
import base64
from typing import Dict, Any, List

def parse_stealer_log(raw_text: str) -> Dict[str, Any]:
    if not raw_text or not raw_text.strip():
        return {
            "status": "error",
            "error": "Empty stealer log payload provided."
        }
    
    text = raw_text.strip()
    
    # 1. Detect Stealer Variant Fingerprints
    variant = "Generic Infostealer"
    if "RedLine" in text or "User.txt" in text and "HWID:" in text:
        variant = "RedLine Stealer"
    elif "Vidar" in text or "password.txt" in text and "MachineID" in text:
        variant = "Vidar / Oski Stealer"
    elif "Lumma" in text or "LummaC2" in text:
        variant = "Lumma Stealer"
    elif "Raccoon" in text or "raccoon" in text.lower():
        variant = "Raccoon Stealer v2"
    elif "Stealc" in text:
        variant = "Stealc Stealer"

    # 2. Extract Credentials (URL, USERNAME, PASSWORD)
    # Common formats:
    # URL: https://example.com
    # Username: victim
    # Password: secretpassword
    # OR url:user:pass
    creds: List[Dict[str, str]] = []
    
    # Pattern 1: Redline/Vidar multi-line
    url_pat = re.compile(r'(?:URL|Host|Site|Domain):\s*(https?://[^\s\r\n]+|[^\s\r\n]+)', re.IGNORECASE)
    user_pat = re.compile(r'(?:Username|User|Login):\s*([^\s\r\n]+)', re.IGNORECASE)
    pass_pat = re.compile(r'(?:Password|Pass):\s*([^\r\n]+)', re.IGNORECASE)
    
    # Split by blocks or iterate
    blocks = re.split(r'(?:\r?\n){2,}|={3,}|-{3,}', text)
    for b in blocks:
        u_m = url_pat.search(b)
        usr_m = user_pat.search(b)
        p_m = pass_pat.search(b)
        if u_m and (usr_m or p_m):
            creds.append({
                "url": u_m.group(1).strip(),
                "username": usr_m.group(1).strip() if usr_m else "N/A",
                "password": p_m.group(1).strip() if p_m else "N/A"
            })
            
    # Pattern 2: Colon delimited URL:USER:PASS
    if not creds:
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("http://") or line.startswith("https://") or (":" in line and line.count(":") >= 2):
                parts = line.split(":")
                if len(parts) >= 3 and not line.startswith("User-Agent"):
                    # check if first part is URL
                    url = parts[0] + ":" + parts[1] if parts[0].startswith("http") else parts[0]
                    rest = parts[2:] if parts[0].startswith("http") else parts[1:]
                    if len(rest) >= 2:
                        creds.append({
                            "url": url,
                            "username": rest[0],
                            "password": ":".join(rest[1:])
                        })

    # 3. Extract Discord Tokens
    # Format: 24-28 chars . 6 chars . 27-38 chars base64-like
    discord_pat = re.compile(r'[\w-]{24,28}\.[\w-]{6}\.[\w-]{27,38}')
    discord_tokens = list(set(discord_pat.findall(text)))

    # 4. Extract Crypto Wallets & Extensions
    wallet_extensions = {
        "MetaMask": "nkbihfbeogaeaoehlefnkodbefgpgknn",
        "Phantom (Solana)": "bfnaelmomeimihpmgjnjophhpkkoljpa",
        "TronLink": "ibnejdfjmmkpcnlpebklmnkoeoihofec",
        "Coinbase Wallet": "hnfanknocfeofbddgcijnmhnfnkdnaad",
        "Binance Chain": "fhbohimaelbohpjbbldcngcnapndodjp",
        "Trust Wallet": "egjidjbpglichdcondbcbdnbeeppgdph",
        "Exodus Web3": "aholpfdialjgjfhomihkjbmgjidlcdno",
        "Ronin Wallet": "fnjhmkhhmkbjkkabndcnnogagogbneec"
    }
    found_wallets = []
    for w_name, ext_id in wallet_extensions.items():
        if ext_id.lower() in text.lower() or w_name.lower() in text.lower():
            found_wallets.append({
                "wallet": w_name,
                "extension_id": ext_id,
                "status": "COMPROMISED_EXT_FOLDER"
            })

    # 5. Extract Hardware & System Profiling
    hwid_m = re.search(r'(?:HWID|Hardware ID|Machine ID|GUID):\s*([a-zA-Z0-9\-_]+)', text, re.IGNORECASE)
    cpu_m = re.search(r'(?:CPU|Processor):\s*([^\r\n]+)', text, re.IGNORECASE)
    gpu_m = re.search(r'(?:GPU|Graphics Card|VideoCard):\s*([^\r\n]+)', text, re.IGNORECASE)
    ram_m = re.search(r'(?:RAM|Memory):\s*([^\r\n]+)', text, re.IGNORECASE)
    ip_m = re.search(r'(?:IP|Client IP|External IP):\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', text, re.IGNORECASE)
    os_m = re.search(r'(?:OS|Operating System|Windows):\s*([^\r\n]+)', text, re.IGNORECASE)
    
    # 6. Extract Cookies & Session Tokens
    cookie_count = len(re.findall(r'(?:Cookie|Set-Cookie|TRUE\tFALSE|\.google\.com|\.facebook\.com|\.twitter\.com)', text, re.IGNORECASE))
    
    # High-Value Target Categorization
    hvt_domains = ["google.com", "binance.com", "coinbase.com", "aws.amazon.com", "github.com", "paypal.com", "apple.com", "bankofamerica.com", "chase.com"]
    hvt_matches = []
    for c in creds:
        for dom in hvt_domains:
            if dom in c["url"].lower():
                hvt_matches.append({
                    "service": dom,
                    "target_url": c["url"],
                    "username": c["username"],
                    "severity": "CRITICAL_ASSET"
                })

    return {
        "status": "success",
        "variant": variant,
        "credentials_count": len(creds),
        "credentials": creds[:100],  # cap for display
        "discord_tokens": discord_tokens,
        "crypto_wallets": found_wallets,
        "cookies_detected": cookie_count,
        "high_value_targets": hvt_matches,
        "system_fingerprint": {
            "hwid": hwid_m.group(1) if hwid_m else "UNKNOWN_OR_STRIPPED",
            "os": os_m.group(1).strip() if os_m else "Windows (Generic)",
            "cpu": cpu_m.group(1).strip() if cpu_m else "N/A",
            "gpu": gpu_m.group(1).strip() if gpu_m else "N/A",
            "ram": ram_m.group(1).strip() if ram_m else "N/A",
            "ip": ip_m.group(1) if ip_m else "N/A"
        },
        "threat_level": "CRITICAL" if (hvt_matches or found_wallets or discord_tokens) else ("ELEVATED" if creds else "INFORMATIONAL")
    }

async def parse_stealer_log_async(raw_text: str) -> Dict[str, Any]:
    return parse_stealer_log(raw_text)
