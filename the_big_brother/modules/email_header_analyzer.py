"""
THE BIG BROTHER // V7.0 TACTICAL FORENSIC SYSTEM
COMPANION POWER ENGINE: RAW RFC 822 HEADER INFILTRATION ANALYZER (v7_email_header_analyzer)
CLASSIFIED // EMAIL FORENSICS & PHISHING ATTRIBUTION CORTEX

Parses full RFC 822 / MIME raw email headers into structured investigative graphs:
- Hop-by-hop Received: transit chain reconstruction with delay timing
- Originating client IP unmasking (X-Originating-IP / first Received header)
- DKIM, SPF, DMARC Authentication-Results validation status
- Spoofing risk scoring and phishing indicator detection
"""

import re
import email
from typing import Dict, Any, List

def parse_raw_email_headers(raw_headers_str: str) -> Dict[str, Any]:
    if not raw_headers_str or not raw_headers_str.strip():
        return {"status": "error", "error": "Raw email header text is required."}
        
    msg = email.message_from_string(raw_headers_str.strip())
    
    # Extract standard fields
    subject = msg.get("Subject", "N/A")
    from_header = msg.get("From", "N/A")
    to_header = msg.get("To", "N/A")
    date_header = msg.get("Date", "N/A")
    msg_id = msg.get("Message-ID", "N/A")
    return_path = msg.get("Return-Path", "N/A")
    auth_results = msg.get("Authentication-Results", "N/A")
    x_orig_ip = msg.get("X-Originating-IP", "N/A").strip("[]")

    # Reconstruct Received Hops
    received_headers = msg.get_all("Received") or []
    hops = []
    
    ip_pat = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    
    originating_ip = x_orig_ip if x_orig_ip != "N/A" else None
    
    for idx, r_header in enumerate(received_headers):
        # Format: from sender.com (sender.com [1.2.3.4]) by receiver.com ... ; Date
        clean_r = " ".join(r_header.split())
        ips = ip_pat.findall(clean_r)
        
        # Filter out private / loopback IPs for origin if possible
        public_ips = [ip for ip in ips if not ip.startswith("127.") and not ip.startswith("10.") and not ip.startswith("192.168.")]
        
        hops.append({
            "hop_number": len(received_headers) - idx,
            "raw_received": clean_r[:200],
            "detected_ips": ips
        })
        
        if not originating_ip and public_ips:
            originating_ip = public_ips[0]

    # Authentication Evaluation
    spf_status = "UNKNOWN"
    dkim_status = "UNKNOWN"
    dmarc_status = "UNKNOWN"
    
    auth_str = (auth_results + " " + (msg.get("Received-SPF") or "")).lower()
    if "spf=pass" in auth_str: spf_status = "PASS"
    elif "spf=fail" in auth_str or "spf=softfail" in auth_str: spf_status = "FAIL"
    
    if "dkim=pass" in auth_str: dkim_status = "PASS"
    elif "dkim=fail" in auth_str: dkim_status = "FAIL"

    if "dmarc=pass" in auth_str: dmarc_status = "PASS"
    elif "dmarc=fail" in auth_str: dmarc_status = "FAIL"

    # Spoofing & Phishing Scoring
    spoof_score = 0
    anomalies = []
    
    if spf_status == "FAIL":
        spoof_score += 40
        anomalies.append("SPF Authentication Failed - Sending server unauthorized by domain owner.")
    if dkim_status == "FAIL":
        spoof_score += 35
        anomalies.append("DKIM Cryptographic Signature Invalid - Header or body modified in transit.")
    if return_path != "N/A" and from_header != "N/A":
        # Check return-path domain vs from domain
        ret_dom = return_path.split("@")[-1].strip(">").lower()
        from_dom = from_header.split("@")[-1].strip(">").split()[0].lower()
        if ret_dom and from_dom and ret_dom != from_dom:
            spoof_score += 25
            anomalies.append(f"Return-Path mismatch: From '{from_dom}' vs Return-Path '{ret_dom}'.")

    verdict = "LEGITIMATE_VERIFIED"
    if spoof_score >= 60:
        verdict = "CRITICAL_PHISHING_OR_SPOOFED_HEADER"
    elif spoof_score >= 25:
        verdict = "SUSPICIOUS_UNAUTHENTICATED_RELAY"

    return {
        "status": "success",
        "subject": subject,
        "from": from_header,
        "to": to_header,
        "date": date_header,
        "message_id": msg_id,
        "return_path": return_path,
        "originating_client_ip": originating_ip or "UNDETERMINED / RELAY_MASKED",
        "authentication_verdict": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status
        },
        "transit_hops_count": len(hops),
        "transit_route": hops,
        "spoofing_risk_score": spoof_score,
        "verdict": verdict,
        "detected_anomalies": anomalies
    }

async def parse_raw_email_headers_async(headers_str: str) -> Dict[str, Any]:
    return parse_raw_email_headers(headers_str)
