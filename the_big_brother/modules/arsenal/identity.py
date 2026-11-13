"""
VX ARSENAL // IDENTITY, TOKEN & FINANCIAL ENGINES

Local-first analyzers:
  jwt_analyzer, password_pwned, vin_decoder, bin_lookup
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import math
import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .common import (
    b64url_decode,
    entropy,
    envelope,
    error_envelope,
    finding,
    http_json,
    http_request,
    risk_grade,
    sha1,
)


# ===========================================================================
# 1. JWT ANALYZER
# ===========================================================================

WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "12345678", "123456789", "qwerty", "admin",
    "jwt", "jwtsecret", "jwt_secret", "supersecret", "super_secret", "changeme",
    "change_me", "letmein", "welcome", "iloveyou", "monkey", "dragon", "sunshine",
    "princess", "football", "baseball", "abc123", "test", "test123", "dev", "development",
    "staging", "production", "prod", "secretkey", "secret_key", "mysecret", "my_secret",
    "your-256-bit-secret", "your_jwt_secret", "signature", "token", "access", "refresh",
    "api", "apikey", "api_key", "key", "private", "default", "example", "sample",
    "bigbrother", "big-brother", "nexus", "sovereign", "application", "backend",
    "flask", "django", "laravel", "node", "nodejs", "express", "spring", "rails",
    "hs256", "rs256", "auth", "authentication", "authorization", "session",
    "0", "1", "12", "123", "1234", "12345", "1234567", "1234567890",
    "password1", "password123", "passw0rd", "p@ssw0rd", "admin123", "root",
    "secret123", "secret1", "s3cr3t", "5ecret", "s3cr3tkey", "hunter2",
    "correcthorsebatterystaple", "correct-horse-battery-staple",
]


def _b64json(segment: str) -> Optional[Dict[str, Any]]:
    try:
        raw = b64url_decode(segment)
        val = json.loads(raw.decode("utf-8"))
        return val if isinstance(val, dict) else None
    except Exception:
        return None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _ts(value: Any) -> Optional[Dict[str, Any]]:
    try:
        n = float(value)
    except Exception:
        return None
    dt = datetime.fromtimestamp(n, tz=timezone.utc)
    delta = (dt - datetime.now(timezone.utc)).total_seconds()
    return {
        "raw": value,
        "iso": dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "seconds_from_now": int(delta),
        "expired": delta < 0,
    }


def _crack_jwt(header: Dict[str, Any], signing_input: str, signature: str) -> Optional[str]:
    alg = str(header.get("alg", "")).upper()
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if not digest:
        return None
    sig_bytes = b64url_decode(signature)
    for secret in WEAK_JWT_SECRETS:
        mac = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), digest).digest()
        if hmac.compare_digest(mac, sig_bytes):
            return secret
    return None


def _analyze_jwt(token: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    token = (token or "").strip().strip('"').strip("'")
    token = re.sub(r"^Bearer\s+", "", token, flags=re.I)
    parts = token.split(".")
    if len(parts) == 5:
        findings.append(finding("info", "JWE encrypted token", "This is a 5-part JWE; only the protected header is readable without the decryption key."))
        header = _b64json(parts[0]) or {}
        return (
            {"type": "JWE", "header": header, "segments": 5, "encrypted": True},
            findings + [finding("low", "Encrypted token", "Claims cannot be inspected without the content-encryption key.")],
            5,
            "JWE token detected; protected header decoded, payload is encrypted.",
        )
    if len(parts) != 3:
        return {}, [finding("info", "Not a compact JWS/JWT", f"Expected 3 dot-separated segments, found {len(parts)}.")], 0, "Invalid JWT structure."

    header = _b64json(parts[0])
    payload = _b64json(parts[1])
    if not header or not payload:
        return {}, [finding("medium", "Malformed JWT segments", "Header or payload is not valid base64url JSON.")], 12, "Malformed JWT."

    alg = str(header.get("alg", "none"))
    typ = str(header.get("typ", ""))
    kid = header.get("kid", "")
    jku = header.get("jku", "")
    x5u = header.get("x5u", "")
    signing_input = parts[0] + "." + parts[1]
    cracked = _crack_jwt(header, signing_input, parts[2])

    exp = _ts(payload.get("exp"))
    nbf = _ts(payload.get("nbf"))
    iat = _ts(payload.get("iat"))
    now = datetime.now(timezone.utc)

    if alg.lower() == "none":
        findings.append(finding("critical", "Unsigned token (alg=none)", "The token declares no signature algorithm. Any client can forge arbitrary claims.", evidence=header, recommendation="Reject alg=none at every verifier and require a signed algorithm."))
    if cracked is not None:
        findings.append(finding("critical", "JWT signed with a weak secret", f"The HMAC secret is the common value '{cracked}'.", evidence="secret recovered via dictionary attack", recommendation="Rotate the signing key to a 256-bit random secret stored in a KMS/secret manager."))
    if alg.upper().startswith("HS") and cracked is None:
        findings.append(finding("medium", "HMAC-signed token", "HS* tokens are only as strong as the shared secret. Test for weak/predictable keys and algorithm confusion.", recommendation="Prefer asymmetric RS256/ES256 and pin the expected algorithm."))
    if str(header.get("crit", "")):
        findings.append(finding("medium", "Critical header extension present", "The token uses a 'crit' header; verify every verifier understands it.", evidence=header.get("crit")))
    if kid:
        findings.append(finding("low", "Key ID (kid) disclosed", f"kid={kid}. If user-controlled, test for path traversal / SQL injection in key lookup.", evidence=kid, recommendation="Resolve kids from a fixed allowlist, never from a file path or query."))
    if jku or x5u:
        findings.append(finding("critical", "Remote key URL in header", "jku/x5u lets the token point verifiers at an attacker-controlled key set.", evidence={"jku": jku, "x5u": x5u}, recommendation="Ignore remote key URLs or pin them to trusted hosts."))
    if exp is None:
        findings.append(finding("high", "No expiration claim", "The token never expires, so theft grants indefinite access.", recommendation="Add short exp values and rotate refresh tokens."))
    elif exp.get("expired"):
        findings.append(finding("info", "Token is expired", f"Expired at {exp.get('iso')}; still test whether the verifier enforces exp.", evidence=exp))
    elif exp.get("seconds_from_now", 0) > 86400 * 30:
        findings.append(finding("medium", "Very long token lifetime", f"Expires in {exp.get('seconds_from_now')//86400} days.", recommendation="Reduce access-token lifetime to minutes/hours and use refresh tokens."))
    if nbf:
        findings.append(finding("info", "Not-before claim present", f"nbf={nbf.get('iso')}"))
    pii = [k for k in ("email", "phone", "phone_number", "address", "ssn", "dob", "birthdate", "name", "given_name", "family_name") if k in payload]
    if pii:
        findings.append(finding("medium", "PII embedded in token", f"Claims expose: {', '.join(pii)}. JWTs are readable by anyone who holds them.", evidence=pii, recommendation="Move PII server-side; keep tokens to opaque subject IDs."))
    privileged = [k for k in ("admin", "is_admin", "role", "roles", "scope", "scopes", "permissions", "groups") if k in payload]
    if privileged:
        findings.append(finding("info", "Authorization claims present", f"Claims: {', '.join(privileged)}. Verify server-side authorization and never trust client role claims alone.", evidence={k: payload[k] for k in privileged}))
    if "sub" not in payload and "client_id" not in payload:
        findings.append(finding("low", "No subject claim", "Neither sub nor client_id is present, making audit attribution difficult."))

    sig_entropy = entropy(parts[2]) if parts[2] else 0
    if parts[2] and sig_entropy < 4.0 and alg.lower() != "none":
        findings.append(finding("medium", "Low-entropy signature segment", f"Signature entropy is {sig_entropy:.2f} bits/char, which is unusual for a real signature.", evidence=parts[2][:40]))

    risk = 0
    for sev, cond in (
        ("critical", alg.lower() == "none"),
        ("critical", cracked is not None),
        ("critical", bool(jku or x5u)),
        ("high", exp is None),
        ("medium", alg.upper().startswith("HS") and cracked is None),
        ("medium", bool(pii)),
        ("medium", bool(exp and exp.get("seconds_from_now", 0) > 86400 * 30)),
        ("low", bool(kid)),
        ("low", "sub" not in payload and "client_id" not in payload),
    ):
        if cond:
            risk += {"critical": 34, "high": 20, "medium": 10, "low": 4}[sev]
    risk = min(100, risk)

    data = {
        "type": "JWS/JWT",
        "header": header,
        "payload": payload,
        "claims": {
            "issuer": payload.get("iss"),
            "subject": payload.get("sub"),
            "audience": payload.get("aud"),
            "issued_at": iat,
            "not_before": nbf,
            "expires": exp,
            "jwt_id": payload.get("jti"),
            "scope": payload.get("scope") or payload.get("scp"),
        },
        "algorithm": alg,
        "type_header": typ,
        "key_id": kid,
        "weak_secret": cracked,
        "signature_entropy": round(sig_entropy, 3),
        "segments": {"header_bytes": len(parts[0]), "payload_bytes": len(parts[1]), "signature_bytes": len(parts[2])},
        "pii_claims": pii,
        "authorization_claims": {k: payload[k] for k in privileged},
    }
    if exp is None:
        expiry_text = "no expiry"
    elif exp.get("expired"):
        expiry_text = "expired"
    else:
        expiry_text = f"expires in {exp.get('seconds_from_now', 0) // 3600}h"
    summary = (
        f"{alg} token with {len(payload)} claims; "
        f"{'weak secret recovered' if cracked else 'no common weak secret'}; "
        f"{expiry_text}; risk {risk}/100."
    )
    return data, findings, risk, summary


async def run_jwt_analyzer(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_jwt, target)
    return envelope(
        "jwt_analyzer", f"JWT // {data.get('algorithm', 'unknown')} TOKEN", risk=risk,
        summary=summary, findings=findings, data=data,
        sources=["Local base64url decode", "HMAC dictionary attack"],
        notes=["No token is transmitted or stored by this tool."],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 2. PWNED PASSWORD CHECK
# ===========================================================================

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "1234567",
    "111111", "1234567890", "123123", "abc123", "1234", "password1", "iloveyou",
    "1q2w3e4r", "000000", "qwerty123", "zaq12wsx", "dragon", "sunshine", "princess",
    "letmein", "654321", "monkey", "27653", "1qaz2wsx", "123321", "qwertyuiop",
    "superman", "asdfghjkl", "welcome", "admin", "login", "passw0rd", "starwars",
    "password123", "password12", "password1234", "qwerty1234", "letmein123",
    "football", "baseball", "whatever", "trustno1", "master", "hello", "freedom",
    "shadow", "michael", "jennifer", "computer", "charlie", "jordan", "hunter",
}


def _password_strength(pw: str) -> Dict[str, Any]:
    length = len(pw)
    lower = bool(re.search(r"[a-z]", pw))
    upper = bool(re.search(r"[A-Z]", pw))
    digits = bool(re.search(r"\d", pw))
    symbols = bool(re.search(r"[^A-Za-z0-9]", pw))
    charset = (26 if lower else 0) + (26 if upper else 0) + (10 if digits else 0) + (33 if symbols else 0)
    ent = length * math.log2(charset) if charset else 0
    issues = []
    if length < 12:
        issues.append("shorter than 12 characters")
    if not upper:
        issues.append("no uppercase letters")
    if not digits:
        issues.append("no digits")
    if not symbols:
        issues.append("no symbols")
    if pw.lower() in COMMON_PASSWORDS:
        issues.append("is a top-common password")
    if re.search(r"(.)\1{2,}", pw):
        issues.append("contains a repeated character run")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf|zxcv)", pw.lower()):
        issues.append("contains a keyboard/numeric sequence")
    if re.search(r"(19|20)\d{2}", pw):
        issues.append("contains a likely year")
    years = re.findall(r"(19|20)\d{2}", pw)
    if years:
        issues.append("contains a date/year pattern")
    if re.fullmatch(r"[A-Z][a-z]+[0-9!@#$%^&*]{1,3}", pw):
        issues.append("matches a common capitalized-word pattern")
    score = min(100, int(ent / 1.2))
    if length < 8:
        score = min(score, 15)
    elif length < 12:
        score = min(score, 45)
    if pw.lower() in COMMON_PASSWORDS:
        score = 0
    score = max(0, score - len(issues) * 3)
    return {
        "length": length,
        "charset_size": charset,
        "entropy_bits": round(ent, 1),
        "score": score,
        "grade": "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "D" if score >= 20 else "F",
        "features": {"lowercase": lower, "uppercase": upper, "digits": digits, "symbols": symbols},
        "issues": issues,
        "masked": (pw[:2] + "*" * max(0, length - 4) + pw[-2:]) if length > 4 else "*" * length,
    }


def _hibp_lookup(password_hash: str) -> Dict[str, Any]:
    prefix = password_hash[:5].upper()
    suffix = password_hash[5:].upper()
    r = http_request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"Add-Padding": "true", "User-Agent": "TheBigBrother-VX-PasswordAudit"},
        timeout=10,
        max_bytes=400000,
    )
    if r.get("status") != 200:
        return {"available": False, "error": r.get("error") or f"HTTP {r.get('status')}", "count": 0}
    count = 0
    for line in (r.get("text") or "").splitlines():
        if ":" in line:
            suf, cnt = line.split(":", 1)
            if suf.strip().upper() == suffix:
                try:
                    count = int(cnt.strip())
                except Exception:
                    count = 0
                break
    return {"available": True, "count": count, "prefix": prefix, "padded": True}


def _analyze_password(pw: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    if not pw:
        return {}, [finding("info", "Empty password", "Nothing to analyze.")], 0, "No password supplied."
    strength = _password_strength(pw)
    digest = sha1(pw).upper()
    hibp = _hibp_lookup(digest)

    if hibp.get("count", 0) > 0:
        count = hibp["count"]
        sev = "critical" if count > 10000 else "high" if count > 100 else "medium"
        findings.append(finding(sev, "Password found in breach corpora", f"This exact password appears {count:,} times in the Pwned Passwords dataset.", evidence=f"{count:,} occurrences", recommendation="Never use this password; rotate it everywhere and enable MFA."))
    elif hibp.get("available"):
        findings.append(finding("info", "Password not found in Pwned Passwords", "No match in the HIBP range corpus. This does not prove it is strong or unused."))
    else:
        findings.append(finding("low", "Breach lookup unavailable", f"Pwned Passwords range API failed: {hibp.get('error')}", recommendation="Retry or use an offline corpus."))

    if strength["issues"]:
        for issue in strength["issues"]:
            sev = "medium" if issue in ("is a top-common password", "shorter than 12 characters") else "low"
            findings.append(finding(sev, f"Password weakness: {issue}", "Pattern reduces effective key space.", recommendation="Use a long random passphrase or a password manager."))
    if strength["entropy_bits"] < 40:
        findings.append(finding("high", "Low entropy", f"Estimated {strength['entropy_bits']} bits of entropy (target ≥ 60-80).", recommendation="Increase length and randomness."))

    risk = 0
    if hibp.get("count", 0) > 0:
        risk += 40 + min(30, int(math.log10(hibp["count"] + 1) * 8))
    if strength["entropy_bits"] < 40:
        risk += 20
    elif strength["entropy_bits"] < 60:
        risk += 10
    risk += len(strength["issues"]) * 3
    if pw.lower() in COMMON_PASSWORDS:
        risk += 20
    risk = min(100, risk)

    summary = (
        f"Password strength {strength['grade']} ({strength['entropy_bits']} bits); "
        f"{'appears ' + format(hibp['count'], ',') + ' times in breaches' if hibp.get('count') else ('not present in Pwned Passwords' if hibp.get('available') else 'breach lookup unavailable')}."
    )
    return {"strength": strength, "breach": hibp, "pwned": hibp.get("count", 0) > 0}, findings, risk, summary


async def run_password_pwned(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_analyze_password, target)
    return envelope(
        "password_pwned", "[REDACTED]", risk=risk, summary=summary, findings=findings, data=data,
        sources=["HIBP Pwned Passwords k-anonymity range API", "Local entropy model"],
        notes=[
            "The plaintext password is never returned or logged.",
            "Only the first 5 characters of its SHA-1 hash are sent (k-anonymity).",
        ],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 3. VIN DECODER
# ===========================================================================

VIN_TRANSLIT = {
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
    "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9,
    "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
}
VIN_WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]
WMI_COUNTRY = {
    "1": "United States", "2": "Canada", "3": "Mexico", "4": "United States",
    "5": "United States", "6": "Australia", "7": "New Zealand", "8": "South America",
    "9": "Brazil", "A": "South Africa", "B": "Angola", "C": "South America",
    "D": "Egypt", "E": "Europe", "F": "Europe", "G": "Europe", "H": "Europe",
    "J": "Japan", "K": "South Korea", "L": "China", "M": "Asia", "N": "Asia",
    "P": "Asia", "R": "Asia", "S": "United Kingdom", "T": "Europe", "U": "Europe",
    "V": "France", "W": "Germany", "X": "Europe", "Y": "Europe", "Z": "Italy",
}


def _vin_check_digit(vin: str) -> Dict[str, Any]:
    if len(vin) != 17:
        return {"valid": False, "reason": "VIN must be 17 characters"}
    if re.search(r"[IOQ]", vin.upper()):
        return {"valid": False, "reason": "VIN cannot contain I, O or Q"}
    total = 0
    for i, ch in enumerate(vin.upper()):
        val = int(ch) if ch.isdigit() else VIN_TRANSLIT.get(ch)
        if val is None:
            return {"valid": False, "reason": f"Invalid character {ch}"}
        total += val * VIN_WEIGHTS[i]
    rem = total % 11
    expected = "X" if rem == 10 else str(rem)
    actual = vin[8].upper()
    return {
        "valid": actual == expected,
        "expected": expected,
        "actual": actual,
        "reason": "Check digit valid" if actual == expected else "Check digit mismatch (may be non-North-American market)",
    }


def _vin_decode(vin: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    vin = re.sub(r"[^A-HJ-NPR-Z0-9]", "", (vin or "").upper())
    if len(vin) != 17:
        return {}, [finding("info", "Invalid VIN length", f"Expected 17 characters, got {len(vin)}.")], 0, "Invalid VIN."
    check = _vin_check_digit(vin)
    if not check["valid"]:
        findings.append(finding("low", "VIN check digit mismatch", check.get("reason", ""), evidence=check))

    r = http_json(
        f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{urllib.parse.quote(vin)}?format=json",
        timeout=12,
    )
    results = (r.get("json") or {}).get("Results", []) if isinstance(r.get("json"), dict) else []
    row = results[0] if results and isinstance(results[0], dict) else {}
    if not row:
        findings.append(finding("medium", "NHTSA decode unavailable", "The vPIC API did not return a decode record."))
        row = {}

    def g(*keys: str) -> str:
        for k in keys:
            v = row.get(k)
            if v not in (None, "", "0", "Not Applicable"):
                return str(v)
        return ""

    decoded = {
        "make": g("Make"),
        "model": g("Model"),
        "model_year": g("ModelYear"),
        "series": g("Series"),
        "trim": g("Trim"),
        "body_class": g("BodyClass"),
        "vehicle_type": g("VehicleType"),
        "manufacturer": g("Manufacturer"),
        "plant_city": g("PlantCity"),
        "plant_country": g("PlantCountry"),
        "plant_company": g("PlantCompanyName"),
        "engine_cylinders": g("EngineCylinders"),
        "displacement_l": g("DisplacementL"),
        "engine_model": g("EngineModel"),
        "fuel_type": g("FuelTypePrimary"),
        "drive_type": g("DriveType"),
        "transmission": g("TransmissionStyle"),
        "gvwr": g("GVWR"),
        "abs": g("ABS"),
        "esc": g("ESC"),
        "traction_control": g("TractionControl"),
        "tpms": g("TPMS"),
        "front_airbags": g("AirBagLocFront"),
        "side_airbags": g("AirBagLocSide"),
        "seat_belts": g("SeatBeltsAll"),
        "doors": g("Doors"),
        "windows": g("Windows"),
        "wmi": vin[:3],
        "vds": vin[3:9],
        "vis": vin[9:],
        "country": WMI_COUNTRY.get(vin[0], "Unknown"),
    }

    recalls: List[Dict[str, Any]] = []
    if decoded["make"] and decoded["model"] and decoded["model_year"]:
        q = (
            f"https://api.nhtsa.gov/recalls/recallsByVehicle?make={urllib.parse.quote(decoded['make'])}"
            f"&model={urllib.parse.quote(decoded['model'])}&modelYear={urllib.parse.quote(decoded['model_year'])}"
        )
        rr = http_json(q, timeout=12)
        rj = rr.get("json") or {}
        if isinstance(rj, dict):
            for rec in (rj.get("results") or [])[:12]:
                recalls.append({
                    "campaign": rec.get("NHTSACampaignNumber", ""),
                    "component": rec.get("Component", ""),
                    "summary": rec.get("Summary", ""),
                    "consequence": rec.get("Consequence", ""),
                    "remedy": rec.get("Remedy", ""),
                    "date": rec.get("ReportReceivedDate", ""),
                })
    if recalls:
        findings.append(finding("high", f"{len(recalls)} recall campaign(s) found", "NHTSA lists safety recalls for this year/make/model. Verify VIN-specific remedy status with a dealer.", evidence=[r["campaign"] for r in recalls[:8]], recommendation="Check the VIN against NHTSA and complete outstanding remedies."))
    else:
        findings.append(finding("info", "No recall campaigns returned", "NHTSA returned no recall records for this year/make/model combination."))

    risk = min(100, len(recalls) * 8 + (10 if not check["valid"] else 0))
    summary = (
        f"{decoded['model_year']} {decoded['make']} {decoded['model']} {decoded['trim']} "
        f"({decoded['body_class'] or 'vehicle'}), built in {decoded['plant_city'] or '?'}, "
        f"{decoded['plant_country'] or '?'}; WMI country {decoded['country']}; "
        f"{len(recalls)} recall campaign(s)."
    )
    data = {
        "vin": vin,
        "check_digit": check,
        "decoded": decoded,
        "recalls": recalls,
        "recall_count": len(recalls),
        "nhtsa_variables_returned": sum(1 for v in row.values() if v not in (None, "", "0")),
        "raw_decode": {k: v for k, v in row.items() if v not in (None, "", "0")},
    }
    return data, findings, risk, summary


async def run_vin_decoder(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_vin_decode, target)
    if not data:
        return error_envelope("vin_decoder", target, summary)
    iocs = [{"type": "vin", "value": data.get("vin", target)}]
    return envelope(
        "vin_decoder", data.get("vin", target), risk=risk, summary=summary, findings=findings,
        data=data, iocs=iocs, sources=["NHTSA vPIC", "NHTSA Recalls API", "WMI registry"],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


# ===========================================================================
# 4. BIN / CARD ISSUER LOOKUP
# ===========================================================================

NETWORK_PREFIXES = (
    ("Visa", [("4", 1)]),
    ("Mastercard", [("51", 2), ("52", 2), ("53", 2), ("54", 2), ("55", 2), ("2221", 4), ("2720", 4)]),
    ("American Express", [("34", 2), ("37", 2)]),
    ("Discover", [("6011", 4), ("65", 2), ("644", 3), ("645", 3), ("646", 3), ("647", 3), ("648", 3), ("649", 3)]),
    ("JCB", [("3528", 4), ("3589", 4)]),
    ("Diners Club", [("300", 3), ("305", 3), ("36", 2), ("38", 2)]),
    ("UnionPay", [("62", 2)]),
    ("Maestro", [("50", 2), ("56", 2), ("57", 2), ("58", 2), ("63", 2), ("67", 2)]),
    ("RuPay", [("60", 2), ("81", 2), ("82", 2), ("508", 3)]),
    ("Elo", [("4011", 4), ("4312", 4), ("4389", 4), ("5041", 4), ("5066", 4), ("5090", 4), ("6277", 4), ("6362", 4)]),
    ("Hipercard", [("6062", 4)]),
)


def _luhn(number: str) -> bool:
    if not number.isdigit():
        return False
    total = 0
    reverse = number[::-1]
    for i, ch in enumerate(reverse):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _infer_network(number: str) -> str:
    for name, prefixes in NETWORK_PREFIXES:
        for pref, _length in prefixes:
            if number.startswith(pref):
                return name
    return "Unknown"


def _bin_lookup(bin_number: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int, str]:
    findings: List[Dict[str, Any]] = []
    raw = re.sub(r"[\s-]", "", (bin_number or ""))
    if not raw.isdigit() or not (6 <= len(raw) <= 19):
        return {}, [finding("info", "Invalid card number", "Enter 6-19 digits (BIN/IIN, or a full card number for validation).")], 0, "Invalid input."
    bin6 = raw[:6]
    bin8 = raw[:8]
    luhn_valid = _luhn(raw) if len(raw) >= 12 else None
    inferred = _infer_network(raw)

    r = http_json(f"https://lookup.binlist.net/{bin8}", timeout=8, headers={"Accept-Version": "3"})
    payload = r.get("json") or {}
    if r.get("status") == 429:
        findings.append(finding("low", "BIN provider rate limited", "Falling back to local prefix inference."))
    data_ok = isinstance(payload, dict) and bool(payload)

    bank = payload.get("bank") or {} if data_ok else {}
    country = payload.get("country") or {} if data_ok else {}
    scheme = str(payload.get("scheme") or inferred).title() if data_ok else inferred
    card_type = str(payload.get("type") or "").title() if data_ok else ""
    brand = str(payload.get("brand") or "") if data_ok else ""
    prepaid = bool(payload.get("prepaid")) if data_ok else False

    if luhn_valid is False:
        findings.append(finding("medium", "Luhn checksum invalid", "The full number fails the Luhn checksum and is not a valid card number.", recommendation="Re-check the number; invalid checksums usually indicate a typo or fabricated data."))
    if prepaid:
        findings.append(finding("medium", "Prepaid / gift card", "The issuer identifies this BIN as prepaid, which carries higher fraud and low-KYC risk.", recommendation="Apply step-up verification for prepaid instruments."))
    if not data_ok:
        findings.append(finding("low", "Issuer metadata unavailable", "binlist.net returned no record; only local prefix inference is shown."))
    if len(raw) >= 12:
        findings.append(finding("info", "PAN supplied", "The input looks like a full card number. Only the BIN was sent to the lookup provider.", evidence=f"{bin6}••••••{raw[-4:]}"))

    risk = 0
    if prepaid:
        risk += 22
    if luhn_valid is False:
        risk += 20
    if scheme == "Unknown":
        risk += 10
    risk = min(100, risk)
    masked = f"{bin6}{'•' * max(0, len(raw) - 10)}{raw[-4:]}" if len(raw) > 10 else f"{bin6}••••"
    summary = (
        f"BIN {bin6} → {scheme} {card_type or 'card'} {('(' + brand + ')') if brand else ''}; "
        f"issuer {bank.get('name') or 'unknown'}, {country.get('name') or 'unknown country'}; "
        f"{'prepaid' if prepaid else 'not flagged prepaid'}; Luhn {'valid' if luhn_valid else 'invalid' if luhn_valid is False else 'not evaluated'}."
    )
    data = {
        "input_masked": masked,
        "bin": bin6,
        "bin8": bin8,
        "card_length": len(raw),
        "luhn_valid": luhn_valid,
        "inferred_network": inferred,
        "scheme": scheme,
        "type": card_type,
        "brand": brand,
        "prepaid": prepaid,
        "country": {"name": country.get("name", ""), "alpha2": country.get("alpha2", ""), "currency": country.get("currency", ""), "emoji": country.get("emoji", "")},
        "bank": {"name": bank.get("name", ""), "url": bank.get("url", ""), "phone": bank.get("phone", ""), "city": bank.get("city", "")},
        "provider": "binlist.net" if data_ok else "local prefix table",
        "provider_status": r.get("status", 0),
    }
    return data, findings, risk, summary


async def run_bin_lookup(target: str) -> Dict[str, Any]:
    started = time.perf_counter()
    data, findings, risk, summary = await asyncio.to_thread(_bin_lookup, target)
    if not data:
        return error_envelope("bin_lookup", target, summary)
    return envelope(
        "bin_lookup", data.get("input_masked", "[REDACTED]"), risk=risk, summary=summary,
        findings=findings, data=data,
        sources=["binlist.net BIN API", "Local IIN prefix registry", "Luhn algorithm"],
        notes=["Only the first 8 digits are transmitted. Never submit card data you are not authorized to handle."],
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )
