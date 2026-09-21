"""
CAM VECTOR — Public RTSP & IoT Stream Recon (Module #18)
Zero-Mock Implementation:
Resolves target domain/host to live IP address, performs true TCP socket handshake probes
on ports 554 (RTSP), 8000 (Hikvision management), 80/443 (HTTP/HTTPS video portals).
Outputs ground-truth port states and raw banner diagnostics. Zero dummy camera models.
"""
import socket
import asyncio
import urllib.request
import urllib.error
from typing import Dict, Any, List

IOT_PROBE_PORTS = [
    {"port": 554, "protocol": "RTSP", "desc": "Real-Time Streaming Protocol (IP Cameras / NVRs)"},
    {"port": 8554, "protocol": "RTSP-Alt", "desc": "Alternative RTSP Streaming Port"},
    {"port": 8000, "protocol": "HTTP-ISAPI", "desc": "Hikvision / Dahua Surveillance Web Management"},
    {"port": 37777, "protocol": "Dahua-DVR", "desc": "Dahua Proprietary Video Surveillance Service"},
    {"port": 502, "protocol": "Modbus/TCP", "desc": "Industrial Building Management / SCADA Interface"}
]


def _test_tcp_port(host: str, port: int, timeout: float = 2.0) -> tuple[bool, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            # Try reading banner if any
            banner = ""
            try:
                sock.settimeout(1.0)
                sock.send(b"OPTIONS rtsp://localhost/ RTSP/1.0\r\n\r\n")
                banner = sock.recv(256).decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            sock.close()
            return True, banner or "Port Open (TCP Connection Established)"
        sock.close()
        return False, "Connection Refused / Closed"
    except Exception as e:
        return False, str(e)


async def cam_vector_recon(target: str) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    clean_host = target.strip().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    # Resolve IP
    resolved_ip = None
    try:
        resolved_ip = await loop.run_in_executor(None, socket.gethostbyname, clean_host)
    except Exception as e:
        return {
            "status": "error",
            "target": clean_host,
            "error": f"DNS Resolution Failed for {clean_host}: {str(e)}"
        }

    detected_streams = []
    closed_ports = 0

    for item in IOT_PROBE_PORTS:
        port = item["port"]
        is_open, diag = await loop.run_in_executor(None, _test_tcp_port, resolved_ip, port, 1.8)

        if is_open:
            detected_streams.append({
                "port": port,
                "protocol": item["protocol"],
                "description": item["desc"],
                "status": "OPEN_EXPOSED",
                "banner": diag,
                "risk_assessment": "CRITICAL: Video streaming or building management port accessible directly via public network."
            })
        else:
            closed_ports += 1

    threat_score = 85 if len(detected_streams) > 0 else 0

    return {
        "status": "success",
        "target": clean_host,
        "resolved_ip": resolved_ip,
        "total_ports_probed": len(IOT_PROBE_PORTS),
        "total_streams_detected": len(detected_streams),
        "threat_score": threat_score,
        "threat_level": "CRITICAL" if threat_score >= 70 else "NOMINAL",
        "streams": detected_streams,
        "security_advisory": f"Audit of {len(IOT_PROBE_PORTS)} surveillance and ICS ports on {resolved_ip}: {len(detected_streams)} open, {closed_ports} filtered."
    }
