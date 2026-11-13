"""
SSL SENTINEL // VX HARDENED CERTIFICATE INTELLIGENCE

Upgraded from a bare certificate dump to a graded TLS posture report:
protocol/cipher, forward secrecy, certificate chain, SAN inventory, expiry
window, serial/SHA-256 fingerprint, key size, issuer trust heuristics and
actionable findings. Pure standard library.
"""
from __future__ import annotations

import datetime
import hashlib
import socket
import ssl
import re
from typing import Any, Dict, List, Optional


def _parse_cert_time(value: str) -> Optional[datetime.datetime]:
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT", "%Y%m%d%H%M%SZ"):
        try:
            return datetime.datetime.strptime(value, fmt).replace(tzinfo=datetime.timezone.utc)
        except Exception:
            continue
    return None


def _name_dict(name) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for rdn in name or []:
        for key, value in rdn:
            out[str(key)] = str(value)
    return out


def _grade(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 72:
        return "B"
    if score >= 58:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _decode_der_cert(der: bytes) -> Dict[str, Any]:
    """Decode a DER certificate without third-party dependencies."""
    if not der:
        return {}
    import tempfile
    import os
    path = ""
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(ssl.DER_cert_to_PEM_cert(der))
            path = fh.name
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:
        return {}
    finally:
        if path:
            try:
                os.unlink(path)
            except Exception:
                pass


def get_ssl_info(domain: str, port: int = 443, _verify: bool = True) -> Dict[str, Any]:
    """
    Connect to a host and return a graded TLS/certificate intelligence report.
    Backwards-compatible keys (issuer, subject, sans, not_before, not_after,
    expired, error) are preserved for existing consumers.
    """
    host = (domain or "").strip().lower()
    host = re.sub(r"^[a-z]+://", "", host).split("/")[0].split(":")[0]
    results: Dict[str, Any] = {
        "domain": host,
        "port": port,
        "issuer": {},
        "subject": {},
        "sans": [],
        "not_before": "",
        "not_after": "",
        "expired": False,
        "error": None,
        "tls_version": "",
        "cipher": "",
        "key_bits": 0,
        "forward_secrecy": False,
        "serial_number": "",
        "sha256_fingerprint": "",
        "days_remaining": None,
        "chain_length": 0,
        "grade": "?",
        "score": 0,
        "issues": [],
        "recommendations": [],
    }
    if not host:
        results["error"] = "Domain is required"
        return results

    results["certificate_verified"] = bool(_verify)
    try:
        ctx = ssl.create_default_context() if _verify else ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True) or b""
                if not cert and der:
                    cert = _decode_der_cert(der)
                cipher = ssock.cipher() or ("", "", 0)
                results["tls_version"] = ssock.version() or ""
                results["cipher"] = cipher[0] or ""
                results["key_bits"] = int(cipher[2] or 0)
                results["forward_secrecy"] = any(x in (cipher[0] or "").upper() for x in ("ECDHE", "DHE"))
                results["issuer"] = _name_dict(cert.get("issuer"))
                results["subject"] = _name_dict(cert.get("subject"))
                results["sans"] = sorted({v for k, v in cert.get("subjectAltName", []) if k == "DNS"})
                results["not_before"] = cert.get("notBefore", "")
                results["not_after"] = cert.get("notAfter", "")
                results["serial_number"] = cert.get("serialNumber", "")
                results["sha256_fingerprint"] = hashlib.sha256(der).hexdigest() if der else ""

                try:
                    chain = ssock.get_verified_chain() if hasattr(ssock, "get_verified_chain") else None
                    results["chain_length"] = len(chain or [])
                except Exception:
                    results["chain_length"] = 0

                nb = _parse_cert_time(results["not_before"])
                na = _parse_cert_time(results["not_after"])
                now = datetime.datetime.now(datetime.timezone.utc)
                if na:
                    results["days_remaining"] = int((na - now).total_seconds() // 86400)
                    results["expired"] = na < now
                if nb and na:
                    results["validity_days"] = max(0, int((na - nb).total_seconds() // 86400))

                score = 100
                issues: List[str] = []
                recs: List[str] = []

                version = results["tls_version"]
                if version == "TLSv1.3":
                    pass
                elif version == "TLSv1.2":
                    score -= 8
                    recs.append("Prefer TLS 1.3 while retaining TLS 1.2 for compatibility.")
                else:
                    score -= 45
                    issues.append(f"Deprecated TLS version negotiated: {version or 'unknown'}")
                    recs.append("Disable TLS 1.0/1.1/SSLv3 at the load balancer.")

                if not results["forward_secrecy"]:
                    score -= 15
                    issues.append("Cipher suite does not provide forward secrecy")
                    recs.append("Prefer ECDHE/DHE cipher suites only.")

                if results["key_bits"] and results["key_bits"] < 128:
                    score -= 20
                    issues.append(f"Weak symmetric key size: {results['key_bits']} bits")
                elif results["key_bits"] and results["key_bits"] < 256:
                    score -= 5

                if results["expired"]:
                    score -= 60
                    issues.append("Certificate is expired")
                    recs.append("Renew immediately and automate renewal.")
                elif results["days_remaining"] is not None:
                    if results["days_remaining"] < 0:
                        score -= 60
                    elif results["days_remaining"] < 15:
                        score -= 22
                        issues.append(f"Certificate expires in {results['days_remaining']} day(s)")
                        recs.append("Renew now; 30-day automated renewal avoids outages.")
                    elif results["days_remaining"] < 30:
                        score -= 8

                issuer_cn = results["issuer"].get("commonName", "")
                subject_cn = results["subject"].get("commonName", "")
                if not issuer_cn or issuer_cn == subject_cn:
                    score -= 25
                    issues.append("Issuer appears untrusted or self-signed")

                if not results["sans"]:
                    score -= 8
                    issues.append("Certificate has no DNS Subject Alternative Names")
                elif not any(host == s or (s.startswith("*.") and host.endswith(s[1:])) for s in results["sans"]):
                    score -= 18
                    issues.append("Hostname does not match any certificate SAN")

                results["score"] = max(0, min(100, score))
                results["grade"] = _grade(results["score"])
                results["issues"] = issues
                results["recommendations"] = recs

    except ssl.SSLCertVerificationError as exc:
        if _verify:
            # Reconnect without verification so the operator still gets the
            # certificate inventory, then explicitly flag the trust failure.
            retry = get_ssl_info(host, port, _verify=False)
            retry["certificate_verified"] = False
            retry["error"] = f"Certificate verification failed: {exc}"
            retry["issues"] = list(dict.fromkeys((retry.get("issues") or []) + [str(exc)]))
            retry["score"] = min(int(retry.get("score") or 0), 25)
            retry["grade"] = "F"
            return retry
        results["error"] = f"Certificate verification failed: {exc}"
        results["issues"].append(str(exc))
        results["score"] = 20
        results["grade"] = "F"
    except Exception as exc:
        results["error"] = f"{type(exc).__name__}: {exc}"

    return results
